import os
from moviepy.editor import VideoFileClip
import openai
from app.config import settings

# Configure OpenAI
if settings.OPENAI_API_KEY:
    openai.api_key = settings.OPENAI_API_KEY

class VideoProcessor:
    """Handles video processing for DLP"""

    @staticmethod
    def extract_audio(video_path: str, output_path: str = "temp_audio.mp3") -> str:
        """
        Extracts audio from a video file and saves it as MP3.
        Returns the path to the audio file.
        """
        try:
            video = VideoFileClip(video_path)
            if video.audio is None:
                return None
            
            video.audio.write_audiofile(output_path, logger=None)
            video.close()
            return output_path
        except Exception as e:
            print(f"Error extracting audio: {e}")
            return None

    @staticmethod
    async def transcribe_audio(audio_path: str) -> dict:
        """
        Transcribes audio file to text using OpenAI Whisper with timestamps.
        Returns: {
            "text": "Full text...",
            "segments": [
                {"start": 0.0, "end": 4.5, "text": "Hello world..."},
                ...
            ]
        }
        """
        if not settings.OPENAI_API_KEY:
            return {"error": "[Error: No OpenAI API Key configured for transcription]"}

        try:
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            with open(audio_path, "rb") as audio_file:
                # Use verbose_json to get segments/timestamps
                response = client.audio.transcriptions.create(
                    model="whisper-1", 
                    file=audio_file,
                    response_format="verbose_json"
                )
            
            # Extract relevant fields
            return {
                "text": response.text,
                "segments": [
                    {
                        "start": seg.start,
                        "end": seg.end,
                        "text": seg.text
                    } for seg in response.segments
                ]
            }
        except Exception as e:
            return {"error": f"[Error during transcription: {str(e)}]"}

    @classmethod
    async def process_video(cls, video_path: str) -> dict:
        """
        Full pipeline: Media -> Audio -> Text (Timestamped)
        Handles both Video (extract audio first) and Audio (direct transcribe).
        Returns dict result.
        """
        # Determine if input is already audio
        is_audio = video_path.lower().endswith(('.mp3', '.wav', '.m4a', '.flac'))
        
        audio_path = video_path if is_audio else f"{video_path}.mp3"
        
        try:
            # 1. Extract Audio (if video)
            if not is_audio:
                extracted_path = cls.extract_audio(video_path, audio_path)
                if not extracted_path:
                    return {"error": "[No audio track found in video]"}
            
            # 2. Transcribe
            # Ensure file exists before transcribing
            if not os.path.exists(audio_path):
                 return {"error": "[Error: Audio file not found for transcription]"}

            result = await cls.transcribe_audio(audio_path)
            return result
            
        finally:
            # Cleanup generated audio file (only if we created it from video)
            if not is_audio and os.path.exists(audio_path):
                os.remove(audio_path)
            

