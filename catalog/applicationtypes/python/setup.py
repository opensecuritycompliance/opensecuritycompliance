# setup.py

from setuptools import setup, find_packages

packages = ["applicationtypes." +
            pack for pack in find_packages("./applicationtypes")]

setup(
    name="applicationtypes",
    version="0.1",
    packages=packages,
)
