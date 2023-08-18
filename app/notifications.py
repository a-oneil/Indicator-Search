import requests
import json
from . import config, color


def console_output(message, indicator=None, output_color=None):
    if indicator:
        if output_color == "BLUE":
            print(f"{color.BLUE}{indicator.id}: {message}{color.ENDCOLOR}")
        elif output_color == "RED":
            print(f"{color.RED}{indicator.id}: {message}{color.ENDCOLOR}")
        else:
            print(f"{indicator.id}: {message}")
    else:
        if output_color == "BLUE":
            print(f"{color.BLUE}{message}{color.ENDCOLOR}")
        elif output_color == "RED":
            print(f"{color.RED}{message}{color.ENDCOLOR}")
        else:
            print(message)


def send_message_to_slack(
    indicator,
    block,
    channel=str(config["SLACK_CHANNEL"]),
    bot_token=str(config["SLACK_BOT_TOKEN"]),
):
    if config["ENABLE_SLACK"] == True:
        try:
            url = "https://slack.com/api/chat.postMessage"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {bot_token}",
            }
            data = {"channel": channel, "blocks": json.dumps(block)}
            response = requests.post(url, headers=headers, json=data)

            if response.status_code != 200:
                raise Exception(
                    f"Slack API returned {response.status_code} with error: {response.text}"
                )
            console_output("Slack Message sent successfully!", indicator, "BLUE")

        except Exception as e:
            console_output(f"Failed to send message {str(e)}", indicator, "RED")


def successful_scan(indicator):
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Indicator Search has succesfully scanned {indicator.indicator}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": " "},
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "View Results",
                },
                "value": "click_me_123",
                "url": f"{config['SERVER_ADDRESS']}/indicator/results/{indicator.id}",
                "action_id": "button-action",
            },
        },
    ]
