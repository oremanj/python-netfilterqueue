import os, sys
from setuptools import setup, Extension

exec(open("netfilterqueue/_version.py", encoding="utf-8").read())

setup_requires = []
try:
    # Use Cython
    from Cython.Build import cythonize

    ext_modules = cythonize(
        Extension(
            "netfilterqueue._impl",
            ["netfilterqueue/_impl.pyx"],
            libraries=["netfilter_queue"],
        ),
        compiler_directives={"language_level": "3str"},
    )
except ImportError:
    # No Cython
    if "egg_info" in sys.argv:
        # We're being run by pip to figure out what we need. Request cython in
        # setup_requires below.
        setup_requires = ["cython"]
    elif not os.path.exists(
        os.path.join(os.path.dirname(__file__), "netfilterqueue/_impl.c")
    ):
        sys.stderr.write(
            "You must have Cython installed (`pip install cython`) to build this "
            "package from source.\nIf you're receiving this error when installing from "
            "PyPI, please file a bug report at "
            "https://github.com/oremanj/python-netfilterqueue/issues/new\n"
        )
        sys.exit(1)
    ext_modules = [
        Extension(
            "netfilterqueue._impl",
            ["netfilterqueue/_impl.c"],
            libraries=["netfilter_queue"],
        )
    ]

setup(
    name="NetfilterQueue",
    version=__version__,
    license="MIT",
    author="Matthew Fox <matt@tansen.ca>, Joshua Oreman <oremanj@gmail.com>",
    author_email="oremanj@gmail.com",
    url="https://github.com/oremanj/python-netfilterqueue",
    description="Python bindings for libnetfilter_queue",
    long_description=open("README.rst", encoding="utf-8").read(),
    packages=["netfilterqueue"],
    ext_modules=ext_modules,
    include_package_data=True,
    exclude_package_data={"netfilterqueue": ["*.c"]},
    setup_requires=setup_requires,
    python_requires=">=3.6",
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
    ],
)
