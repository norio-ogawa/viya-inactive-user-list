Here I'll jot down my improvement ideas, implementations I want to change, and tips for reducing processing time.

# Unevaluated ideas

## Add users who are not logged in to the LOGON_YYYYMMDD dataset
That way, simply by examining the dataset, it's easier to check for users who haven't logged in or users who haven't logged in for a long period.
Specific changes include adding records that do not match the DAYS variable and user list to the LOGON_YYYYMMDD dataset.
We believe this will enable us to delete records with missing DAYS values and drop the DAYS variable when cross-referencing the user list with past logon history.

This idea is scrapped. We can simply save it to the same library as the logon history using the macro's OUT= parameter.

# Ideas I'm trying to implement

# Ideas already implemented