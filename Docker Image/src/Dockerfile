FROM nixos/nix as nixImage

COPY bin /root/bin

RUN apk update && apk add bash && apk add curl && apk add git 
# && apk add --update py-pip
# RUN pip install pandas

WORKDIR /root

RUN ["mkdir", "-p", "codesecure"]

RUN ["/bin/bash", "-c", "/root/bin/install-fluid-attacks.sh"]
# RUN ["/bin/bash", "-c", "/root/bin/install-aws-cli.sh"]
# RUN ["bin/bash", "-c", "/root/bin/sonarcloud-scan.sh"]
# CMD ["/bin/bash"]

# RUN ["/root/bin/clone-repo.sh"]
# ENTRYPOINT ["/root/bin/clone-repo.sh"]
# CMD ["/root/bin/clone-repo.sh"]
# CMD ["/bin/bash"]
# RUN ["skims","scan","config.yaml"]

FROM amancevice/pandas:1.3.3
WORKDIR /root/
RUN ["mkdir", "-p", "codesecure"]
COPY --from=nixImage /root/bin/LogProcessor.py /root/codesecure
COPY --from=nixImage /root/codesecure/results.csv /root/codesecure
COPY --from=nixImage /root/bin/upload-to-bucket.sh /root/codesecure
RUN apt-get update
RUN apt-get install sudo
RUN sudo apt-get -y install python3-pip
RUN sudo apt-get -y install wkhtmltopdf
RUN pip install requests
RUN pip install matplotlib
RUN pip install numpy
RUN pip install pdfkit
RUN pip3 --no-cache-dir install --upgrade awscli
WORKDIR /root/codesecure/
RUN python LogProcessor.py 
# RUN ["python", "LogProcessor.py"]
CMD ["/bin/bash", "-c", "/root/codesecure/upload-to-bucket.sh"]
#Write the code to push report.pdf in the current directory to s3 bucket 
# CMD ["/bin/bash"]