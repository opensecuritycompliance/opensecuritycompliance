# For better task development,

1.	Handle negative test cases effectively by ensuring the use of valid variables. For instance, if accessing a key like 

	`highCount = vulnerability_CloseToSLAHigh['results'][0]['count(data)']`, perform validation using our internal utility library. An example would be:
				`from compliancecow.utils import dictutils

				if dictutils.is_valid_array(vulnerability_CloseToSLAHigh, "results") and dictutils.is_valid_array(vulnerability_CloseToSLAHigh["results"][0], "count(data)'"):

					highCount = vulnerability_CloseToSLAHigh['results'][0]['count(data)']`


2.	Return errors promptly instead of nesting 'if' conditions. For instance:

		For example we can rewrite the above example into,

			`if not dictutils.is_valid_array(vulnerability_CloseToSLAHigh, "results") or not dictutils.is_valid_array(vulnerability_CloseToSLAHigh["results"][0], "count(data)'"):

				return {"error":"invalid data"}`


3.	When handling try, catch blocks, aim to handle specific exceptions rather than catching all exceptions. This approach helps identify what exceptions might have been overlooked.

4.	Instead of using print statements, prioritize returning errors with detailed information. This practice enhances error handling and provides better context for debugging and resolving issues.

5.	Please refrain from creating a local file unless there is a specific reason to do so. We've noticed this occurring in some instances.

6.	Try to avoid using inner methods in Python whenever possible.

7.	About using pandas library,

    *.	Please ensure to verify the availability of columns before accessing them.

    *.	For optimal performance when performing operations on columns, please adhere to the following preferred order:

        1. Utilize vectorization techniques.
        2. Employ custom Cython routines.
        3. Utilize the `apply` method, prioritizing:
            - Reducing operations that can be executed in Cython.
            - Iterating within the Python space.
        4. Use `itertuples`.
        5. Consider `iterrows`.
        6. As a last resort, update an empty DataFrame, such as using `loc` one row at a time.

8.  If your rule generates a file, consider exporting it in Parquet format. This format is advantageous as it handles data size efficiently.

