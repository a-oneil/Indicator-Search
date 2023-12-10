from openai import OpenAI
from .. import config


async def get_indicator_summary(results):
    try:
        summary = ""
        if not config["OPENAI_ENABLED"]:
            return None

        if config["OPENAI_API_KEY"] == "":
            return None

        if not config["OPENAI_MODEL"]:
            return None

        if not results:
            return None

        client = OpenAI(api_key=config["OPENAI_API_KEY"])
        completion = client.chat.completions.create(
            model=config["OPENAI_MODEL"],
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior security analyst and need to explain the results of json that are given to you.",
                },
                {
                    "role": "user",
                    "content": f"Without jumping to conclusions on the results, provide a detailed summary in a paragraph. If there are tools with no results, dont mention them in the paragraph at all. {str(results)}",
                },
            ],
        )

        summary = str(completion.choices[0].message.content)

        return summary if summary else None

    except Exception:
        return None
