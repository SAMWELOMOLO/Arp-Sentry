Usage
=====

This section provides a detailed guide on how to use the ARP Spoofing Detection Tool.

Installation
------------

1. Clone the repository:
   .. code-block:: bash

       git clone https://github.com/SAMWELOMOLO/ARP-Spoofing-Detection.git

2. Navigate to the project directory:
   .. code-block:: bash

       cd ARP-Spoofing-Detection

3. Install the dependencies:
   .. code-block:: bash

       pip install -r requirements.txt

Running the Tool
----------------

1. Ensure you have the necessary permissions to run the tool (root or sudo access).

2. Run the tool:
   .. code-block:: bash

       python src/arpsentry.py

3. Use the GUI to manage the whitelist and blacklist.

Docker Deployment
-----------------

1. Build the Docker image:
   .. code-block:: bash

       docker build -t arpsentry .

2. Run the Docker container:
   .. code-block:: bash

       docker run -it --net=host arpsentry

