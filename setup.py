#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="openshift-scc-ai-agent",
    version="1.0.0",
    author="OpenShift SCC AI Agent",
    author_email="admin@example.com",
    description="An intelligent AI-powered tool for analyzing Kubernetes/OpenShift YAML manifests and generating Security Context Constraints",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/openshift-scc-ai-agent",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "scc-ai-agent=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.yaml", "*.md", "*.txt"],
    },
    keywords="openshift kubernetes security scc ai agent",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/openshift-scc-ai-agent/issues",
        "Source": "https://github.com/yourusername/openshift-scc-ai-agent",
        "Documentation": "https://github.com/yourusername/openshift-scc-ai-agent/blob/main/README.md",
    },
) 