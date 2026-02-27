import asyncio
import os
import logging

logger = logging.getLogger(__name__)

# Lazy-loaded faster-whisper model singleton (CPU, int8 quantised)
_whisper_model = None


def _get_whisper_model():
    global _whisper_model
    if _whisper_model is None:
        from faster_whisper import WhisperModel
        logger.info("Loading faster-whisper 'base' model (first-use, CPU)...")
        _whisper_model = WhisperModel("base", device="cpu", compute_type="int8")
        logger.info("faster-whisper model ready")
    return _whisper_model


class VideoProcessor:
    """Handles video/audio processing for DLP scanning.

    Transcription runs entirely on-server via faster-whisper — no data is
    sent to any external API.
    """

    @staticmethod
    def extract_audio(video_path: str, output_path: str = "temp_audio.mp3") -> str:
        """Extract audio track from a video file, return path to MP3."""
        try:
            from moviepy.editor import VideoFileClip
            video = VideoFileClip(video_path)
            if video.audio is None:
                return None
            video.audio.write_audiofile(output_path, logger=None)
            video.close()
            return output_path
        except Exception as e:
            logger.error(f"Error extracting audio: {e}")
            return None

    @staticmethod
    async def transcribe_audio(audio_path: str) -> dict:
        """Transcribe an audio file using local faster-whisper.

        Returns:
            {"text": "...", "segments": [{"start": 0.0, "end": 4.5, "text": "..."}], "language": "en"}
            or {"error": "..."} on failure.
        """
        def _run():
            model = _get_whisper_model()
            segments, info = model.transcribe(audio_path, beam_size=5)
            segment_list = []
            full_text_parts = []
            for seg in segments:
                full_text_parts.append(seg.text.strip())
                segment_list.append({
                    "start": round(seg.start, 2),
                    "end": round(seg.end, 2),
                    "text": seg.text.strip(),
                })
            return {
                "text": " ".join(full_text_parts),
                "segments": segment_list,
                "language": info.language,
            }

        try:
            return await asyncio.to_thread(_run)
        except Exception as e:
            logger.error(f"Transcription failed: {e}")
            return {"error": f"[Error during transcription: {str(e)}]"}

    @classmethod
    async def process_video(cls, video_path: str) -> dict:
        """Full pipeline: video/audio file → transcribed text with timestamps."""
        is_audio = video_path.lower().endswith(('.mp3', '.wav', '.m4a', '.flac'))
        audio_path = video_path if is_audio else f"{video_path}.mp3"

        try:
            if not is_audio:
                extracted = cls.extract_audio(video_path, audio_path)
                if not extracted:
                    return {"error": "[No audio track found in video]"}

            if not os.path.exists(audio_path):
                return {"error": "[Audio file not found for transcription]"}

            return await cls.transcribe_audio(audio_path)

        finally:
            if not is_audio and os.path.exists(audio_path):
                os.remove(audio_path)
