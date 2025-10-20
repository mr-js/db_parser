# db_parser
 Database dump parser with multi-core support

 ![db_parser](/images/db_parser_1.png)

 ## Usage

 ### Setup

 Just extract the database dumps to any directory and specify it in file [db_parser.toml](/db_parser/db_parser.toml) (DB_PATH)
 
 ### Run
 Just run [db_parser.py](/db_parser/db_parser.py) and follow the on-screen instructions: the results will be in [report.txt](/db_parser/report.txt)

 ## Examples
 
 ![db_parser](/images/db_parser_2.png)

## Remarks

> [!CAUTION]
 > This project does not contain personal data of any people. The examples above, including database dump names and obfuscated content fragments, are provided solely as an example as possible content to be processed by the utility.
 
> [!NOTE]
> The utility supports acceleration due to multi-core mode support, while the identification and utilization of the maximum available number of processor cores is performed in automatic mode. Automatic transliteration of full name is also supported (only Russian language for now).