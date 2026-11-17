use std::path::Path;
use std::time::Duration;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ctr::cipher::{KeyIvInit, StreamCipher};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use id3::TagLike;

use crate::api::downloads::MangoRights;
use crate::api::types::{AlignedWord, Clip};
use crate::cli::{DownloadFormat, DownloadSource};
use crate::errors::CliError;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

pub async fn download_clip(
    client: &crate::api::SunoClient,
    clip: &Clip,
    output_dir: &str,
    format: DownloadFormat,
    source: DownloadSource,
    quiet: bool,
) -> Result<String, CliError> {
    if source == DownloadSource::Mango {
        return download_clip_mango(client, clip, output_dir, format, quiet).await;
    }
    let resolved = client.download_source(source, format).await?;
    if resolved == DownloadSource::Mango {
        return download_clip_mango(client, clip, output_dir, format, quiet).await;
    }
    let url = match client.prepare_download(clip, format, resolved).await {
        Ok(url) => url,
        Err(e) if source == DownloadSource::Auto => {
            if !quiet {
                eprintln!("Official download unavailable ({e}), falling back to mango playback decryption...");
            }
            return download_clip_mango(client, clip, output_dir, format, quiet).await;
        }
        Err(e) => return Err(e),
    };
    match transfer(clip, output_dir, format.extension(), &url, quiet).await {
        Err(CliError::Http(e)) if matches!(e.status().map(|s| s.as_u16()), Some(401 | 403)) => {
            let fresh = client
                .prepared_download_url(&clip.id, format, resolved)
                .await?;
            transfer(clip, output_dir, format.extension(), &fresh, quiet).await
        }
        result => result,
    }
}

fn is_ftyp(bytes: &[u8]) -> bool {
    bytes.len() > 8 && &bytes[4..8] == b"ftyp"
}

fn is_webm(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == [26, 69, 223, 163]
}

fn is_valid_mango_container(bytes: &[u8], ext: &str) -> bool {
    if ext == "webm" {
        is_webm(bytes)
    } else {
        is_ftyp(bytes)
    }
}

fn unwrap_mango_secret(
    kek_bytes: &[u8],
    b64_wrapped: &str,
    clip_id: &str,
) -> Result<Vec<u8>, CliError> {
    let wrapped = BASE64
        .decode(b64_wrapped)
        .map_err(|e| CliError::Download(format!("invalid base64 in mango rights: {e}")))?;
    if wrapped.len() < 13 {
        return Err(CliError::Download("mango rights key/iv too short".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(kek_bytes)
        .map_err(|_| CliError::Download("invalid KEK length".into()))?;
    let nonce = Nonce::from_slice(&wrapped[..12]);
    let payload = Payload {
        msg: &wrapped[12..],
        aad: clip_id.as_bytes(),
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CliError::Download("AES-GCM key unwrap failed".into()))
}

pub fn decrypt_mango_audio(
    mut data: Vec<u8>,
    ext: &str,
    clip_id: &str,
    jwt: Option<&str>,
    rights: &MangoRights,
) -> Result<Vec<u8>, CliError> {
    if is_valid_mango_container(&data, ext) {
        return Ok(data);
    }
    let kek_input = jwt
        .or(rights.glt.as_deref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::Download("missing JWT or guest token for mango decryption".into()))?;
    let kek = Sha256::digest(kek_input.as_bytes());
    let key_raw = unwrap_mango_secret(&kek, &rights.key, clip_id)?;
    let iv_raw = unwrap_mango_secret(&kek, &rights.iv, clip_id)?;
    let mut ctr = Aes128Ctr::new_from_slices(&key_raw, &iv_raw)
        .map_err(|_| CliError::Download("invalid AES-128-CTR key/iv length".into()))?;
    ctr.apply_keystream(&mut data);
    if !is_valid_mango_container(&data, ext) {
        return Err(CliError::Download(format!(
            "mango decrypted audio is not a valid {ext} container"
        )));
    }
    Ok(data)
}

async fn download_clip_mango(
    client: &crate::api::SunoClient,
    clip: &Clip,
    output_dir: &str,
    format: DownloadFormat,
    quiet: bool,
) -> Result<String, CliError> {
    if clip.status != "complete" {
        return Err(CliError::Download(format!(
            "clip {} is {}; wait for completion with `suno status {} --wait`",
            clip.id, clip.status, clip.id
        )));
    }
    let mut media_list = clip.media_urls.clone();
    let mut image_url = clip.image_url.clone();
    if crate::api::SunoClient::select_mango_media(&media_list).is_none() {
        let detailed = client.clip_detail(&clip.id).await?;
        media_list = detailed.media_urls;
        if image_url.is_none() {
            image_url = detailed.image_url;
        }
    }
    let media = crate::api::SunoClient::select_mango_media(&media_list).ok_or_else(|| {
        CliError::Download(format!(
            "no progressive M4A/WebM playback stream found for clip {}",
            clip.id
        ))
    })?;
    let raw_ext = if media.content_type == "webm-opus" {
        "webm"
    } else {
        "m4a"
    };

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CliError::Http(e.without_url()))?;

    let resp = http
        .get(&media.url)
        .send()
        .await
        .map_err(|e| CliError::Http(e.without_url()))?
        .error_for_status()
        .map_err(|e| CliError::Http(e.without_url()))?;

    let enc_bytes = resp
        .bytes()
        .await
        .map_err(|e| CliError::Http(e.without_url()))?
        .to_vec();

    let plain_bytes = if is_valid_mango_container(&enc_bytes, raw_ext) {
        enc_bytes
    } else {
        let rights = client.mango_rights(&clip.id).await?;
        let jwt = client.current_jwt();
        decrypt_mango_audio(enc_bytes, raw_ext, &clip.id, jwt.as_deref(), &rights)?
    };

    let target_ext = format.extension();
    let filename = clip_filename(&clip.title, &clip.id, target_ext);
    tokio::fs::create_dir_all(output_dir).await?;
    let final_path = Path::new(output_dir).join(&filename);
    let uid = uuid::Uuid::new_v4();
    let raw_tmp = final_path.with_extension(format!("{raw_ext}.{uid}.raw.part"));
    let out_tmp = final_path.with_extension(format!("{target_ext}.{uid}.part"));

    tokio::fs::write(&raw_tmp, &plain_bytes).await?;

    if format == DownloadFormat::M4a && raw_ext == "m4a" {
        if let Err(e) = tokio::fs::rename(&raw_tmp, &final_path).await {
            let _ = tokio::fs::remove_file(&raw_tmp).await;
            return Err(e.into());
        }
        return Ok(std::fs::canonicalize(&final_path)?.display().to_string());
    }

    if !quiet {
        eprintln!("Transcoding decrypted {raw_ext} to {target_ext} via ffmpeg...");
    }

    let transcode_res = transcode_with_ffmpeg(
        &http,
        &raw_tmp,
        &out_tmp,
        format,
        image_url.as_deref(),
    )
    .await;
    let _ = tokio::fs::remove_file(&raw_tmp).await;
    if let Err(e) = transcode_res {
        let _ = tokio::fs::remove_file(&out_tmp).await;
        return Err(e);
    }

    if let Err(e) = validate_audio_file(&out_tmp, target_ext).await {
        let _ = tokio::fs::remove_file(&out_tmp).await;
        return Err(e);
    }
    if let Err(e) = tokio::fs::rename(&out_tmp, &final_path).await {
        let _ = tokio::fs::remove_file(&out_tmp).await;
        return Err(e.into());
    }
    Ok(std::fs::canonicalize(&final_path)?.display().to_string())
}

async fn transcode_with_ffmpeg(
    http: &reqwest::Client,
    input_path: &Path,
    output_path: &Path,
    format: DownloadFormat,
    image_url: Option<&str>,
) -> Result<(), CliError> {
    let mut cmd = tokio::process::Command::new("ffmpeg");
    cmd.arg("-y").arg("-v").arg("error");

    let mut cover_tmp = None;
    if format == DownloadFormat::Mp4
        && let Some(url) = image_url.filter(|u| u.starts_with("https://"))
        && let Ok(resp) = http.get(url).send().await
        && let Ok(resp) = resp.error_for_status()
        && let Ok(bytes) = resp.bytes().await
    {
        let tmp_img = output_path.with_extension("cover.jpg.part");
        if tokio::fs::write(&tmp_img, &bytes).await.is_ok() {
            cover_tmp = Some(tmp_img);
        }
    }

    if let Some(ref img) = cover_tmp {
        cmd.arg("-loop").arg("1").arg("-i").arg(img);
    }
    cmd.arg("-i").arg(input_path);

    match format {
        DownloadFormat::Mp3 => {
            cmd.args(["-vn", "-c:a", "libmp3lame", "-q:a", "2", "-f", "mp3"]);
        }
        DownloadFormat::Wav => {
            cmd.args(["-vn", "-c:a", "pcm_s16le", "-f", "wav"]);
        }
        DownloadFormat::M4a => {
            cmd.args(["-vn", "-c:a", "aac", "-b:a", "192k", "-f", "ipod"]);
        }
        DownloadFormat::Mp4 => {
            if cover_tmp.is_some() {
                cmd.args([
                    "-c:v",
                    "libx264",
                    "-tune",
                    "stillimage",
                    "-pix_fmt",
                    "yuv420p",
                    "-vf",
                    "scale=trunc(iw/2)*2:trunc(ih/2)*2",
                    "-c:a",
                    "aac",
                    "-b:a",
                    "192k",
                    "-shortest",
                    "-movflags",
                    "+faststart",
                    "-f",
                    "mp4",
                ]);
            } else {
                cmd.args(["-c:a", "aac", "-b:a", "192k", "-f", "mp4"]);
            }
        }
    }
    cmd.arg(output_path);

    let output = cmd.output().await.map_err(|e| {
        CliError::Download(format!(
            "failed to run ffmpeg for transcoding (is ffmpeg installed?): {e}"
        ))
    });
    if let Some(img) = cover_tmp {
        let _ = tokio::fs::remove_file(img).await;
    }
    let output = output?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Download(format!(
            "ffmpeg transcoding failed: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

async fn transfer(
    clip: &Clip,
    output_dir: &str,
    ext: &str,
    url: &str,
    quiet: bool,
) -> Result<String, CliError> {
    let filename = clip_filename(&clip.title, &clip.id, ext);
    // Create the target dir up front: generation has already spent credits by
    // the time we download, so a missing `--download` dir must not error out.
    tokio::fs::create_dir_all(output_dir).await?;
    let path = Path::new(output_dir).join(&filename);
    // Stream into a sibling `.part` and only rename into place on full success,
    // so an interrupted or truncated transfer never leaves a file that looks
    // like a finished download.
    let part_path = path.with_extension(format!("{ext}.{}.part", uuid::Uuid::new_v4()));

    // Bounded client: connect timeout, per-read inactivity timeout (catches a
    // stalled CDN mid-stream), and an overall cap. Without these a hung
    // connection would block the download forever.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| CliError::Http(e.without_url()))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CliError::Http(e.without_url()))?
        .error_for_status()
        .map_err(|e| CliError::Http(e.without_url()))?;

    let total = resp.content_length().unwrap_or(0);
    let pb = if quiet {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(total)
    };
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40}] {bytes}/{total_bytes} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
    );
    pb.set_message(filename.clone());

    let written = match stream_to_file(&part_path, resp, &pb).await {
        Ok(n) => n,
        Err(e) => {
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(e);
        }
    };

    // Reject a short read against the advertised size instead of tagging a
    // truncated MP3 downstream.
    if written == 0 || (total > 0 && written != total) {
        let _ = tokio::fs::remove_file(&part_path).await;
        return Err(CliError::Download(format!(
            "incomplete download: received {written} of {total} bytes for {filename}"
        )));
    }

    // A 200 response can still be an expired-link HTML/JSON error page.
    // Check the container before giving the file its final audio extension.
    if let Err(e) = validate_audio_file(&part_path, ext).await {
        let _ = tokio::fs::remove_file(&part_path).await;
        return Err(e);
    }
    if let Err(e) = tokio::fs::rename(&part_path, &path).await {
        let _ = tokio::fs::remove_file(&part_path).await;
        return Err(e.into());
    }
    pb.finish_with_message("done");

    Ok(std::fs::canonicalize(&path)?.display().to_string())
}

async fn validate_audio_file(path: &Path, ext: &str) -> Result<(), CliError> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut header = [0u8; 12];
    let count = file.read(&mut header).await?;
    let valid = match ext {
        "mp3" => {
            count >= 3
                && (header.starts_with(b"ID3") || (header[0] == 0xff && header[1] & 0xe0 == 0xe0))
        }
        "wav" => {
            count >= 12
                && (header.starts_with(b"RIFF") || header.starts_with(b"RF64"))
                && &header[8..12] == b"WAVE"
        }
        "m4a" | "mp4" => count >= 12 && &header[4..8] == b"ftyp",
        _ => false,
    };
    if !valid {
        return Err(CliError::Download(format!(
            "response is not a valid {ext} container; no final file was saved"
        )));
    }
    Ok(())
}

/// Stream a response body to `part_path`, returning the byte count written.
/// The caller removes the partial file on any error.
async fn stream_to_file(
    part_path: &Path,
    resp: reqwest::Response,
    pb: &ProgressBar,
) -> Result<u64, CliError> {
    use tokio::io::AsyncWriteExt as _;
    let mut file = tokio::fs::File::create(part_path).await?;
    let mut stream = resp.bytes_stream();
    let mut written: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| CliError::Http(e.without_url()))?;
        pb.inc(chunk.len() as u64);
        written += chunk.len() as u64;
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(written)
}

/// Build `<title-slug>-<id8>.<ext>`. Runs of non-alphanumeric chars collapse
/// to a single `-` (a naive `replace("--", "-")` leaves `--` behind for 3+
/// char runs), and empty/symbol-only titles must not yield a leading dash.
fn clip_filename(title: &str, id: &str, ext: &str) -> String {
    let mut slug = String::new();
    for c in title.to_lowercase().chars() {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    if slug.ends_with('-') {
        slug.pop();
    }
    // Bound the UTF-8 filename and tolerate unexpected IDs without panics.
    while slug.len() > 180 {
        slug.pop();
    }
    let slug = slug.trim_end_matches('-');
    let short_id: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(8)
        .collect();
    if slug.is_empty() {
        format!("{short_id}.{ext}")
    } else {
        format!("{slug}-{short_id}.{ext}")
    }
}

/// Embed lyrics and metadata into an MP3 file using ID3v2 tags.
/// - USLT: unsynchronized (plain) lyrics — shown in most players
/// - SYLT: synchronized lyrics with word timestamps — shown in Apple Music, Spotify, etc.
/// - TIT2: title, TPE1: artist
pub fn embed_lyrics_in_mp3(
    mp3_path: &str,
    title: &str,
    plain_lyrics: Option<&str>,
    aligned_words: Option<&[AlignedWord]>,
) -> Result<(), CliError> {
    let mut tag = id3::Tag::read_from_path(mp3_path).unwrap_or_else(|_| id3::Tag::new());

    // Set title
    tag.set_title(title);

    // Plain lyrics (USLT) — shown in most players
    if let Some(lyrics) = plain_lyrics {
        tag.add_frame(id3::frame::Lyrics {
            lang: "eng".to_string(),
            description: String::new(),
            text: lyrics.to_string(),
        });
    }

    // Synchronized lyrics (SYLT) — timed word-by-word display
    if let Some(words) = aligned_words {
        let content: Vec<(u32, String)> = words
            .iter()
            .filter(|w| w.success)
            .map(|w| ((w.start_s * 1000.0) as u32, w.word.clone()))
            .collect();

        if !content.is_empty() {
            tag.add_frame(id3::frame::SynchronisedLyrics {
                lang: "eng".to_string(),
                timestamp_format: id3::frame::TimestampFormat::Ms,
                content_type: id3::frame::SynchronisedLyricsType::Lyrics,
                description: String::new(),
                content,
            });
        }
    }

    tag.write_to_path(mp3_path, id3::Version::Id3v24)
        .map_err(|e| CliError::Download(format!("failed to write ID3 tags: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_successful_http_error_pages_before_saving_audio() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let _ = stream.read(&mut request).unwrap();
            let body = "<html>expired signed URL</html>";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let clip:Clip=serde_json::from_value(serde_json::json!({"id":"test","title":"test","status":"complete","model_name":"chirp-hawk","created_at":"now"})).unwrap();
        let result = transfer(
            &clip,
            dir.path().to_str().unwrap(),
            "mp3",
            &format!("http://{address}/audio"),
            true,
        )
        .await;
        server.join().unwrap();
        assert!(matches!(result, Err(CliError::Download(_))));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn filename_collapses_separator_runs() {
        assert_eq!(
            clip_filename("Hello, World!", "0123456789abcdef", "mp3"),
            "hello-world-01234567.mp3"
        );
        // 3+ char symbol run — the old replace("--","-") left "--" behind.
        assert_eq!(
            clip_filename("a — b", "0123456789abcdef", "mp3"),
            "a-b-01234567.mp3"
        );
    }

    #[test]
    fn filename_handles_empty_and_symbol_only_titles() {
        // No leading dash when the title slugs away to nothing.
        assert_eq!(clip_filename("", "0123456789abcdef", "mp3"), "01234567.mp3");
        assert_eq!(
            clip_filename("!!!", "0123456789abcdef", "mp4"),
            "01234567.mp4"
        );
    }

    #[test]
    fn filename_keeps_unicode_titles() {
        assert_eq!(
            clip_filename("夜の歌 Remix", "0123456789abcdef", "mp3"),
            "夜の歌-remix-01234567.mp3"
        );
        assert_eq!(clip_filename("short", "abc", "mp3"), "short-abc.mp3");
    }

    #[test]
    fn decrypts_mango_m4a_and_webm_with_jwt_or_glt() {
        for (ext, plain) in [
            ("m4a", &[0, 0, 0, 12, b'f', b't', b'y', b'p', 0][..]),
            ("webm", &[26, 69, 223, 163, 0, 0, 0, 0, 0][..]),
        ] {
            for use_jwt in [true, false] {
                let clip_id = "synthetic-id";
                let token = if use_jwt {
                    "synthetic-session"
                } else {
                    "synthetic-guest"
                };
                let key_raw = [7u8; 16];
                let iv_raw = [8u8; 16];

                let mut encrypted = plain.to_vec();
                let mut ctr = Aes128Ctr::new_from_slices(&key_raw, &iv_raw).unwrap();
                ctr.apply_keystream(&mut encrypted);

                let kek = Sha256::digest(token.as_bytes());
                let gcm = Aes256Gcm::new_from_slice(&kek).unwrap();
                let wrap = |secret: &[u8], nonce_byte: u8| -> String {
                    let nonce_bytes = [nonce_byte; 12];
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let ciphertext = gcm
                        .encrypt(
                            nonce,
                            Payload {
                                msg: secret,
                                aad: clip_id.as_bytes(),
                            },
                        )
                        .unwrap();
                    let mut combined = nonce_bytes.to_vec();
                    combined.extend_from_slice(&ciphertext);
                    BASE64.encode(combined)
                };

                let rights = MangoRights {
                    key: wrap(&key_raw, 1),
                    iv: wrap(&iv_raw, 2),
                    glt: if use_jwt {
                        None
                    } else {
                        Some(token.to_string())
                    },
                };

                let out = decrypt_mango_audio(
                    encrypted,
                    ext,
                    clip_id,
                    if use_jwt { Some(token) } else { None },
                    &rights,
                )
                .unwrap();
                assert_eq!(out, plain);

                let unencrypted_out = decrypt_mango_audio(
                    plain.to_vec(),
                    ext,
                    clip_id,
                    None,
                    &MangoRights {
                        key: String::new(),
                        iv: String::new(),
                        glt: None,
                    },
                )
                .unwrap();
                assert_eq!(unencrypted_out, plain);
            }
        }
    }
}
