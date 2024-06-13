# SmartSpaceOccupancy

This repository contains the code and resources for predicting daily office occupancy using a combination of internal and open-source data. 
The project leverages data from internal APIs and open-source platforms such as Open-Meteo and the Community of Madrid Open Data Catalog.

## Project Structure

The repository is organized as follows:
- **InternalData_Extraction/**
	- **api_extraction.py**: The main script to extracting CSV files with information from the internal origins APIs.
	- **api_utilities.py**: Contains functions for handling APIs and extracting data from internal APIs.
- **InternalData_Transformation.ipynb**: Jupyter notebook for the transformation of the extracted internal data.
- **OpenData.ipynb**: Jupyter notebook for the extraction and transformation of open-source data.
- **PredictionModel.ipynb**: Jupyter notebook for constructing the prediction model, including all steps from data preprocessing to model evaluation.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/SmartSpaceOccupancy.git
    ```
2. Navigate to the project directory:
    ```bash
    cd SmartSpaceOccupancy
    ```
