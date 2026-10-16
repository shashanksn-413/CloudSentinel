import json
import logging
import boto3
from src.shared.db_helpers import store_response_log

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2", region_name="us-east-2")


def isolate_instance(alert, instance_id):
    """Isolate an EC2 instance by replacing its security groups with a deny-all group."""
    if not instance_id:
        logger.warning("No instance_id provided for isolation")
        return None

    try:
        isolation_sg_id = get_or_create_isolation_sg(instance_id)

        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = instance_info.get("Reservations", [])
        if not reservations:
            raise Exception(f"Instance {instance_id} not found")

        instance = reservations[0]["Instances"][0]
        original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        vpc_id = instance.get("VpcId", "")

        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )

        logger.info(f"Isolated instance {instance_id}: replaced SGs {original_sgs} with {isolation_sg_id}")

        store_response_log({
            "alert_id": alert.get("alert_id", ""),
            "action_type": "ec2_isolate",
            "target": instance_id,
            "status": "success",
            "details": f"Replaced SGs {original_sgs} with isolation SG {isolation_sg_id} in VPC {vpc_id}"
        })

        return {
            "action": "ec2_isolate",
            "target": instance_id,
            "original_security_groups": original_sgs,
            "isolation_security_group": isolation_sg_id,
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Failed to isolate instance {instance_id}: {str(e)}")
        store_response_log({
            "alert_id": alert.get("alert_id", ""),
            "action_type": "ec2_isolate",
            "target": instance_id,
            "status": "failed",
            "details": str(e)
        })
        return {
            "action": "ec2_isolate",
            "target": instance_id,
            "status": "failed",
            "error": str(e)
        }


def get_or_create_isolation_sg(instance_id):
    """Get or create a deny-all security group for isolation."""
    sg_name = "cloudsentinel-isolation"

    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
    vpc_id = instance_info["Reservations"][0]["Instances"][0]["VpcId"]

    try:
        response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [sg_name]},
                {"Name": "vpc-id", "Values": [vpc_id]}
            ]
        )
        if response["SecurityGroups"]:
            return response["SecurityGroups"][0]["GroupId"]
    except Exception:
        pass

    response = ec2_client.create_security_group(
        GroupName=sg_name,
        Description="CloudSentinel isolation - no inbound or outbound traffic",
        VpcId=vpc_id
    )
    sg_id = response["GroupId"]

    ec2_client.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )

    logger.info(f"Created isolation security group {sg_id} in VPC {vpc_id}")
    return sg_id