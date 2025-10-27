from setuptools import setup, find_packages

setup(
    name='reconx',
    version='0.1.0',
    author='Jules',
    author_email='',
    description='A CLI-first reconnaissance tool for Kali Linux',
    packages=find_packages(),
    install_requires=[
        'rich',
        'google-generativeai',
    ],
    entry_points={
        'console_scripts': [
            'reconx = reconx.__main__:main'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3.8',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
