FROM continuumio/miniconda3

COPY bin /app

WORKDIR "/app" 

RUN conda install --file requirements.txt


ENTRYPOINT [ "python3" ]
CMD [ "Dashboard.py" ]

