"""Synapse policy: plaintext messages and removal of room encryption are forbidden."""
from synapse.module_api import ModuleApi


class SecureRooms:
    def __init__(self, config: dict, api: ModuleApi):
        self.api = api
        api.register_third_party_rules_callbacks(check_event_allowed=self.check_event_allowed)

    async def check_event_allowed(self, event, state):
        if event.type in ("m.room.message", "m.sticker"):
            return False, None
        if event.type == "m.room.encryption":
            return event.content.get("algorithm") == "m.megolm.v1.aes-sha2", None
        if event.type == "m.room.redaction":
            target = event.get_dict().get("redacts") or event.content.get("redacts")
            encryption = state.get(("m.room.encryption", ""))
            if encryption and target == encryption.event_id:
                return False, None
        return True, None
