from setuptools import setup, Extension

setup(name="tsadecode",
      version="0.6",
      description="Decoding utilities for ZUN data",
      author="32th-System",
      author_email="intensonat@gmail.com",
      url="https://github.com/32th-System/py-tsadecode",
      license="Unlicense",
      ext_modules=[Extension(
        name="tsadecode",
        sources=["tsadecode.cpp"],
        language="C++",
        extra_compile_args=['-std=c++11'],
        extra_link_args=["-lstdc++"]
      )])
