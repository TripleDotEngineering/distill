from setuptools import setup

setup(
    name = 'distill',
    version = '0.1.0',
    packages = ['distill'],
    install_requires = [
        'trivium-cli',
        'networkx'
    ],
    entry_points = {
        'console_scripts': [
            'distill = distill.__main__:entry'
        ]
    }
)