import boto3
import os
from typing import Optional
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class StorageManager:
    """Handles file storage interactions with DigitalOcean Spaces (S3 compatible)"""

    def __init__(self):
        self.enabled = bool(settings.DO_SPACES_KEY and settings.DO_SPACES_SECRET)
        if self.enabled:
            self.client = boto3.client(
                's3',
                region_name=settings.DO_SPACES_REGION,
                endpoint_url=settings.DO_SPACES_ENDPOINT,
                aws_access_key_id=settings.DO_SPACES_KEY,
                aws_secret_access_key=settings.DO_SPACES_SECRET
            )
            self.bucket = settings.DO_SPACES_BUCKET
        else:
            logger.warning("Cloud storage disabled: Missing credentials")

    async def upload_file(self, file_path: str, object_name: Optional[str] = None) -> Optional[str]:
        """
        Upload a file to the configured Space.
        Returns the public URL if successful, None otherwise.
        """
        if not self.enabled:
            return None

        if object_name is None:
            object_name = os.path.basename(file_path)

        try:
            # Upload file
            extra_args = {'ACL': 'public-read'} # Make file PUBLIC so it can be downloaded via URL
            
            # Helper to run blocking upload in thread
            import asyncio
            from functools import partial
            
            await asyncio.get_event_loop().run_in_executor(
                None, 
                partial(
                    self.client.upload_file, 
                    file_path, 
                    self.bucket, 
                    object_name, 
                    ExtraArgs=extra_args
                )
            )

            # Construct URL
            # Format: https://{bucket}.{endpoint}/{object_name}
            # Note: endpoint usually includes region e.g. sgp1.digitaloceanspaces.com
            # We need to strip https:// to reconstruct cleanly or use virtual host style
            
            endpoint_host = settings.DO_SPACES_ENDPOINT.replace("https://", "").replace("http://", "")
            url = f"https://{self.bucket}.{endpoint_host}/{object_name}"
            
            return url

        except Exception as e:
            logger.error(f"Failed to upload to cloud storage: {e}")
            return None

    def delete_file(self, file_url: str) -> bool:
        """
        Delete a file from cloud storage using its URL or object key.
        """
        if not self.enabled or not file_url:
            return False
            
        try:
            # Extract object name from URL
            # URL: https://{bucket}.{endpoint}/{object_name}
            # Key is everything after the host
            from urllib.parse import urlparse
            path = urlparse(file_url).path
            object_name = path.lstrip('/')
            
            self.client.delete_object(Bucket=self.bucket, Key=object_name)
            return True
        except Exception as e:
            logger.error(f"Failed to delete file {file_url}: {e}")
            return False

    def set_lifecycle_policy(self, days: int = 7) -> bool:
        """
        Configure the bucket to automatically expire files after N days.
        """
        if not self.enabled: 
            return False
            
        try:
            lifecycle_config = {
                'Rules': [
                    {
                        'ID': f'Expire after {days} days',
                        'Status': 'Enabled',
                        'Prefix': '',  # Apply to all files
                        'Expiration': {'Days': days}
                    }
                ]
            }
            self.client.put_bucket_lifecycle_configuration(
                Bucket=self.bucket,
                LifecycleConfiguration=lifecycle_config
            )
            return True
        except Exception as e:
            logger.error(f"Failed to set lifecycle policy: {e}")
            return False
