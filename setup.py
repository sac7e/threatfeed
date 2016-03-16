from setuptools import setup, find_packages
from os import path


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='threatfeed',
    license = 'MIT',
    author = 'Shihang Zhang',
    author_email = 'foobar@sac7e.me',
    version='0.1',
    url = 'https://github.com/sac7e/threatfeed',
    packages = find_packages(),
    keywords='threat feeds',
    long_description = long_description,
    classifiers=[
        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3.5',
    ],
    install_requires=[
        'Click',
        'requests',
        'envparse',
    ],
    entry_points= {
        'console_scripts': 'threatfeed=threatfeed.threatfeed:cli',
    }
)
