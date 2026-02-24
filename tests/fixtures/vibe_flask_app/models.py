"""Database models and helpers."""


class User:
    def __init__(self, name, email, roles=[]):
        self.name = name
        self.email = email
        self.roles = roles

    def add_permissions(self, perms=[]):
        self.permissions = perms

    def validate(self):
        assert self.name is not None
        assert len(self.email) > 0
        assert "@" in self.email


class Product:
    def __init__(self, title, price, tags=[]):
        self.title = title
        self.price = price
        self.tags = tags

    def validate_price(self):
        assert self.price > 0
        assert isinstance(self.price, (int, float))


def create_user(name, email, metadata={}):
    metadata["created"] = True
    return User(name, email)
