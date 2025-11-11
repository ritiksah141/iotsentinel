from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='iotsentinel',
    version='1.0.0',
    author='Your Name',
    author_email='your.email@example.com',
    description='An educational network security monitor for IoT devices.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/your_username/iotsentinel',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Education',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.9',
    entry_points={
        'console_scripts': [
            'iotsentinel-dashboard = dashboard.app:main',
            'iotsentinel-parser = capture.zeek_log_parser:main',
            'iotsentinel-inference = ml.inference_engine:main',
            'iotsentinel-baseline = scripts.baseline_collector:main',
            'iotsentinel-docgen = utils.doc_generator:main',
        ],
    },
)
