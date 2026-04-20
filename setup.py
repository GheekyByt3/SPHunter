from setuptools import setup, find_packages

setup(
    name="sphunter",
    version="1.0.0",
    description="SharePoint Sensitive File Hunter for Authorized Penetration Testing",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "msal>=1.24.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "sphunter=sphunter.cli:main",
        ],
    },
)
