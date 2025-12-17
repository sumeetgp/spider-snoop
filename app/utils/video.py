import os
from moviepy import VideoFileClip
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
    async def transcribe_audio(audio_path: str) -> str:
        """
        Transcribes audio file to text using OpenAI Whisper.
        """
        if not settings.OPENAI_API_KEY:
            return "[Error: No OpenAI API Key configured for transcription]"

        try:
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            with open(audio_path, "rb") as audio_file:
                transcript = client.audio.transcriptions.create(
                    model="whisper-1", 
                    file=audio_file,
                    response_format="text"
                )
            return transcript
        except Exception as e:
            return f"[Error during transcription: {str(e)}]"

    @classmethod
    async def process_video(cls, video_path: str) -> str:
        """
        Full pipeline: Video -> Audio -> Text
        """
        audio_path = f"{video_path}.mp3"
        
        try:
            # 1. Extract Audio
            extracted_path = cls.extract_audio(video_path, audio_path)
            if not extracted_path:
                return "[No audio track found in video]"
            
            # 2. Transcribe
            text = await cls.transcribe_audio(extracted_path)
            return text
            
        finally:
            # Cleanup audio file
            if os.path.exists(audio_path):
                os.remove(audio_path)
