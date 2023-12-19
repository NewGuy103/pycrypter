from setuptools import setup, find_packages

setup(
    name='newguy103-pycrypter',
    version='1.0.0',
    packages=find_packages(),  # Define the package name
    py_modules=['pycrypter.__init__', 'pycrypter._methods'],  # Add modules explicitly
    install_requires=['cryptography'],
    author='NewGuy103',
    author_email='userchouenthusiast@gmail.com',
    description='Simple cryptography wrapper created with threading.',
    long_description_content_type='text/markdown',
    long_description=open('README.md').read(),
    url='https://github.com/newguy103/pycrypter',
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
)

