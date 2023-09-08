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
            data = {
                "channel": channel,
                "username": "Indicator Search",
                "icon_url": "https://raw.githubusercontent.com/rc-austinoneil/Indicator-Search/master/app/static/images/icon.png",
                "blocks": json.dumps(block),
            }
            response = requests.post(url, headers=headers, json=data)

            if response.status_code != 200:
                raise Exception(response.text)
            console_output("Slack message sent", output_color="BLUE")
        except Exception as e:
            console_output(f"Slack message failed {str(e)}", output_color="RED")


def slack_indicator_complete(indicator, result="success"):
    def flatten_dict(d, parent_key="", sep="\n"):
        for key, value in d.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            if isinstance(value, dict):
                yield from flatten_dict(value, new_key, sep=sep)
            else:
                yield f"{new_key.replace('_', ' ').title()}: {value}"

    if result == "success":
        block = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Scan Complete:* {indicator.indicator.replace('http', 'hxxp').replace('.', '[.]')}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": "*Type:*"},
                    {"type": "plain_text", "text": f"{indicator.indicator_type}"},
                    {"type": "mrkdwn", "text": "*Created by:*"},
                    {"type": "plain_text", "text": f"{indicator.username}"},
                    {"type": "mrkdwn", "text": "*Tags:*"},
                    {
                        "type": "plain_text",
                        "text": f"{', '.join(flatten_dict(indicator.tags)) if indicator.tags else 'None'}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": " "},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Results :mag:"},
                    "value": "click_me_123",
                    "url": f"{config['SERVER_ADDRESS']}/indicator/results/{indicator.id}",
                    "action_id": "button-action",
                },
            },
        ]
    elif result == "failure":
        block = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{config['SERVER_ADDRESS']}/indicator/results/{indicator.id}|Indicator {indicator.id}> encountered an error during scanning.",
                },
            }
        ]
    send_message_to_slack(block)
