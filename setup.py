from setuptools import find_packages
from setuptools import setup

setup(
    name="OpenAIAuth",
    version="3.0.0",
    license="MIT",
    author="pengzhile",
    author_email="acheong@student.dalat.org",
    description="OpenAI Authentication Reverse Engineered",
    packages=find_packages("src"),
    package_dir={"": "src"},
    py_modules=["OpenAIAuth"],
    url="https://github.com/acheong08/OpenAIAuth",
    project_urls={"Bug Report": "https://github.com/acheong08/OpenAIAuth/issues/new"},
    install_requires=[
        "tls_client",
    ],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    long_description=open("README.md", "rt", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
)
