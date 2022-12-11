from setuptools import setup

setup(
    name='wizzDownload',
    packages=['downloads'],
    include_package_data=True,
    install_requires=[
        'tqdm',
        'six',
        'requests',
    ],
    extras_require={
        "dev": ["numpy", "codecov", "pytest", "pytest-cov"],
        "sphinx": ["matplotlib", "pandas", "sphinx", "sphinx-gallery", "pillow"],
    },
)
