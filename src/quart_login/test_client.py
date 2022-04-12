from quart.testing import QuartClient


class QuartLoginClient(QuartClient):
    """
    A Quart test client that knows how to log in users
    using the Quart-Login extension.
    """

    async def update_session_transaction(self, user=None, fresh_login=True):
        if user:
            async with self.session_transaction() as sess:
                sess["_user_id"] = user.get_id()
                sess["_fresh"] = fresh_login
