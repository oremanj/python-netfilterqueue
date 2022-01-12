from setuptools import setup, Extension

VERSION = "0.8.1" # Remember to change CHANGES.txt and netfilterqueue.pyx when version changes.

try:
    # Use Cython
    from Cython.Build import cythonize
    ext_modules = cythonize(
        Extension(
            "netfilterqueue", ["netfilterqueue.pyx"], libraries=["netfilter_queue"]
        ),
        compiler_directives={"language_level": "3str"},
    )
except ImportError:
    # No Cython
    ext_modules = [
        Extension("netfilterqueue", ["netfilterqueue.c"], libraries=["netfilter_queue"])
    ]

setup(
    ext_modules=ext_modules,
    name="NetfilterQueue",
    version=VERSION,
    license="MIT",
    author="Matthew Fox",
    author_email="matt@tansen.ca",
    url="https://github.com/oremanj/python-netfilterqueue",
    description="Python bindings for libnetfilter_queue",
    long_description=open("README.rst").read(),
    download_url="http://pypi.python.org/packages/source/N/NetfilterQueue/NetfilterQueue-%s.tar.gz" % VERSION,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ]
)
