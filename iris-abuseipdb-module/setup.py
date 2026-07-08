from setuptools import setup, find_packages

setup(
    name='iris_abuseipdb_module',
    version='1.2.1',
    packages=find_packages(),  # <-- Isto vai encontrar automaticamente todos os pacotes
    author="DFIR-IRIS",
    author_email="contact@dfir-iris.org",
    description="An interface module for AbuseIPDB and DFIR-IRIS",
    long_description="An interface module for AbuseIPDB and DFIR-IRIS",
    long_description_content_type="text/markdown",
    url="https://github.com/dfir-iris/iris-client",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: LGPLv3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "abuseipdb-wrapper",
        "setuptools",
        "pyunpack"
    ],
    include_package_data=True,
    zip_safe=False,
)