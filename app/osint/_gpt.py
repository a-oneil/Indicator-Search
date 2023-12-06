from openai import OpenAI
from .. import config


def get_indicator_summary(results):
    try:
        if config["OPENAI_API_KEY"] == "":
            return None

        if not results:
            return None

        client = OpenAI(api_key=config["OPENAI_API_KEY"])
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
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
        return completion.choices[0].message.content
    except Exception as e:
        return str(e)
