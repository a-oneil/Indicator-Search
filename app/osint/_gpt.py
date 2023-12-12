from openai import OpenAI
from .. import config, notifications
from ..models import Indicators
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified


async def summary_handler(indicator, db: Session):
    try:
        # fmt: off
        notifications.console_output(indicator=indicator, message="Summarizing results", output_color="BLUE")
        indicator = Indicators.get_indicator_by_id(indicator.id, db)
        indicator.summary = (await get_indicator_summary(indicator.results) if indicator.results else None)      
        tags_dict = indicator.tags if indicator.tags else {}
        tags_dict.update({"summary": True})
        indicator.tags = tags_dict
        flag_modified(indicator, "tags")
        db.add(indicator)
        db.commit()
        notifications.console_output(indicator=indicator, message="Summarizing complete", output_color="BLUE")
        # fmt: on
    except Exception:
        db.rollback()
        indicator = Indicators.get_indicator_by_id(indicator.id, db)
        indicator.summary = "An error occurred while summarizing the results."
        db.add(indicator)
        db.commit()


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
