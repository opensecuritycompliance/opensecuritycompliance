# setup.py

from setuptools import setup, find_packages

packages = ["appconnections." +
            pack for pack in find_packages("./appconnections")]

setup(
    name="appconnections",
    version="0.1",
    packages=packages,
)
