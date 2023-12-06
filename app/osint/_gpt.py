from openai import OpenAI
from .. import config


def get_indicator_summary(results, summary_queue=None):
    def update_queue(summary, summary_queue=None):
        if summary_queue:
            summary_queue.put(summary)

    try:
        summary = ""
        if not config["OPENAI_ENABLED"]:
            update_queue(summary, summary_queue)
            return None

        if config["OPENAI_API_KEY"] == "":
            update_queue(summary, summary_queue)
            return None

        if not config["OPENAI_MODEL"]:
            update_queue(summary, summary_queue)
            return None

        if not results:
            update_queue(summary, summary_queue)
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

        summary = completion.choices[0].message.content
        if not summary:
            update_queue(summary, summary_queue)
            return None

        update_queue(summary, summary_queue)
        return summary
    except Exception:
        update_queue("", summary_queue)
        return None
