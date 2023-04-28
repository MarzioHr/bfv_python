# University of Essex - Master Thesis

The Design of a Homomorphic Encryption Library for the Resource-constrained IoT with Efficiency Objectives

## Project Introduction
Homomorphic encryption is a theoretical solution to overcome several new privacy and security concerns that emerged with the increasing popularity of the Internet of Things. However, homomorphic encryptions also require an increased resource overhead on the often resource-constrained IoT end device. This dissertation aims to explore the impact of homomorphic encryption schemes on the device while optimising efficiency. The main contribution of this dissertation to the field of research is the implementation of a homomorphic encryption scheme using the NumPy Python library. 

The goal of the implementation is to create a resource-efficient encryption library that is easy to understand, yet easily applicable within IoT systems. Different encryption schemes were benchmarked using a PoC IoT application to explore this viability. 

## Repository Structure
The core BFV Python encryption library can be found in the module `bfv_python.py`, whereas the unit tests that were run to verify the code outputs can be found in the script `unittest.py`.

The subfolder “PoC” contains all files related to the created proof-of-concept IoT application. Inside, there are folders containing the different docker image files, python scripts and requirements to emulate the end device, controller, and evaluation stack.

The subfolder “collected_data” contains all gathered raw data from the benchmark tests which were used to create the graphs in Section 5.

## Validation and Verification
Throughout the project, two main levels of testing were utilised to validate and verify the quality of the implementation:
*	Unit Testing
*	Continuous Review via Linters

A unit test is a way of testing a unit - the smallest piece of code that can be logically isolated in a system. In most programming languages, that is a function, a subroutine, a method, or property (Olan, 2003). In the Python BFV homomorphic encryption scheme implementation, the outputs of the various functions, such as the key generation, encryption, decryption, and evaluations, are tested to confirm that they fulfil expectations in terms of typing and results. In the case of the dissertation implementation, the testing was done instead via print-based unit tests due to limited time. While developing and adjusting the code, print statements were used to verify the outputs of functions and ensure that the individual units of the library are working as expected. A test script has been included in the project’s GitHub repository and can be run to validate the library’s outputs. 

Continuous source code review is done to ensure that the structure, style, complexity, syntax, and security aspect of the source code is guaranteed. This can be done with the help of static code analysis tools called linters. For this project, two main Python linters were utilised. Pylint was used to verify the styling and the Bandit linter was used to cover security aspects of the code.

![Pylint Final Score](https://i.imgur.com/r19I0ZR.png)

*Figure 1: Pylint Final Score for Encryption Library Source Code.*

![Bandit's Final Run](https://i.imgur.com/IalRnEa.png)

*Figure 2: Bandit's Final Run with No Issues Found.*

## Conclusion
The results showed that while the conventional RSA encryption was more efficient, the homomorphic encryption alternatives required resources that still fall in an acceptable range for modern IoT devices. 

In conclusion, the viability of homomorphic encryption is highly dependent on the underlying application’s use case, its number of interconnected nodes, the frequency of events or readings, the available network infrastructure, as well as the complexity of the required evaluations and operations on the data. In simple use cases where collected data needs to either be added or multiplied frequently, homomorphic encryption and the schemes specifically building upon BFV pose a viable approach that should be explored for that specific application.
