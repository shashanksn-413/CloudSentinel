import json
import logging
import boto3
from src.shared.db_helpers import store_response_log

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = boto3.client("iam", region_name="us-east-2")


def revoke_access_key(alert):
    """Disable an IAM user's access keys when compromise is detected."""
    actor = alert.get("actor", "")
    
    if "user/" in actor:
        username = actor.split("user/")[-1]
    else:
        username = actor

    if not username or username in ["root", "unknown"]:
        logger.warning(f"Cannot revoke keys for actor: {actor}")
        return None

    try:
        response = iam_client.list_access_keys(UserName=username)
        keys_disabled = []

        for key_meta in response.get("AccessKeyMetadata", []):
            key_id = key_meta["AccessKeyId"]
            if key_meta["Status"] == "Active":
                iam_client.update_access_key(
                    UserName=username,
                    AccessKeyId=key_id,
                    Status="Inactive"
                )
                keys_disabled.append(key_id)
                logger.info(f"Disabled access key {key_id} for user {username}")

        response_record = store_response_log({
            "alert_id": alert.get("alert_id", ""),
            "action_type": "iam_key_revoke",
            "target": username,
            "status": "success",
            "details": f"Disabled {len(keys_disabled)} access key(s): {keys_disabled}"
        })

        return {
            "action": "iam_key_revoke",
            "target": username,
            "keys_disabled": keys_disabled,
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Failed to revoke keys for {username}: {str(e)}")
        store_response_log({
            "alert_id": alert.get("alert_id", ""),
            "action_type": "iam_key_revoke",
            "target": username,
            "status": "failed",
            "details": str(e)
        })
        return {
            "action": "iam_key_revoke",
            "target": username,
            "status": "failed",
            "error": str(e)
        }