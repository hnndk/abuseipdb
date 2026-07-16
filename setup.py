from setuptools import setup, find_packages

setup(
    name='iris_abuseipdb_module',
    version='1.2.1',
    packages=find_packages(),
    author="DFIR-IRIS",
    author_email="contact@dfir-iris.org",
    description="An interface module for AbuseIPDB and DFIR-IRIS",
    install_requires=[
        'requests>=2.25.0',
        'iris-interface>=1.0.0'
    ],
    python_requires='>=3.7'
)