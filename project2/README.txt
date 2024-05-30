hello!

to run my program, first make sure you have all the libraries downloaded:
    - pip install requests
    - pip install dnspython
    - pip install ntplib
    - pip install prompt_toolkit

then, in your terminal:
    1. ensure you are in the correct directory
    2. enter: sudo python3 monitoring_service.py
        * might be "sudo python networks.py" if you are running a version of python < 3
    3. you will be asked for your password, enter that, press enter

    in a seperate terminal:
    4. enter: sudo python3 management_app.py
    5. you will be asked for your password, enter that, press enter

    then the code should be running!


Once the code is running, to stop the program:
    1. you can do control c (^C), which will stop the program --> if you are running macOS