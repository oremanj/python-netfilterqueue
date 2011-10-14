from distutils.core import setup, Extension

VERSION = "0.3" # Remember to change README.rst when version changes.

try:
    # Use Cython
    from Cython.Distutils import build_ext
    cmd = {"build_ext": build_ext}
    ext = Extension(
            "netfilterqueue",
            sources=["netfilterqueue.pyx",],
            libraries=["netfilter_queue"],
        )
except ImportError:
    # No Cython
    cmd = {}
    ext = Extension(
            "netfilterqueue",
            sources = ["netfilterqueue.c"],
            libraries=["netfilter_queue"],
        )

setup(
    cmdclass = cmd,
    ext_modules = [ext],
    name="NetfilterQueue",
    version=VERSION,
    license="BSD",
    author="Matthew Fox",
    author_email="matthew@kerkhofftech.ca",
    url="https://github.com/kti/python-netfilterqueue",
    description="Python bindings for libnetfilter_queue",
    long_description=open("README.rst").read(),
    download_url="http://pypi.python.org/packages/source/N/NetfilterQueue/NetfilterQueue-%s.tar.gz" % VERSION,
    classifiers = [
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 2",
    ]
)
