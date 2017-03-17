from setuptools import setup


setup(
    name='holepunch',
    version='0.0.0',
    description="Punch holes in your AWS account security",
    author='Erik Price',
    url='https://github.com/erik/holepunch',
    packages=['holepunch'],
    entry_points={
        'console_scripts': [
            'holepunch = holepunch:main',
        ],
    },
    license='MIT',
    install_requires=[
        'boto3==1.4.4',
        'docopt==0.6.2',
        'ipgetter==0.6',
    ]
)
