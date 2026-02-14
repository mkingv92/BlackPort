from setuptools import setup, find_packages

setup(
    name="fastscan-x",
    version="1.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "fastscan=main:main"
        ]
    },
)
