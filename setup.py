from setuptools import setup

# Metadata goes in setup.cfg. These are here for GitHub's dependency graph.
setup(
    name="Quart-Login",
    install_requires=[
        "Quart>=0.17.0",
        "Werkzeug>=2.0.0",
    ],
)
