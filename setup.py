from setuptools import find_packages
from setuptools import setup

setup(
    name="OpenAIAuth",
    version="0.0.3.1",
    license="GNU General Public License v2.0",
    author="Rawand Ahmed Shaswar and Antonio Cheong",
    author_email="acheong@student.dalat.org",
    description="OpenAI Authentication Reverse Engineered",
    packages=find_packages("src"),
    package_dir={"": "src"},
    url="https://github.com/acheong08/OpenAIAuth",
    install_requires=[
        "tls-client",
    ],
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
)
