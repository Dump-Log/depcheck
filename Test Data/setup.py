from setuptools import setup, find_packages

setup(
    name="example-project",
    version="1.0.0",
    description="Example project for DepCheck testing",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "requests==2.28.0",
        "flask==2.0.0",
        "numpy==1.24.0",
        "panadas==0.2",
        "scikit-learns==0.1.0",
        "panda==0.3.1",
        "nump==7.29.0",
    ],
)
