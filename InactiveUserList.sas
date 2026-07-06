/* This program matches user information with AUDIT records to create a dataset of the most recent login times. */
options nosource;

/* Define the base URL for the REST API. */
%macro defineBaseUrl(mode=0);
  %global _audit_url;
  %global _identities_url;

  %if &mode=0 %then %do;
    %let _audit_url=%sysget(SAS_SERVICES_URL);
    %let _identities_url=%sysget(SAS_SERVICES_URL);
  %end;
  %else %do;
    %let _audit_url=https://%sysget(SAS_AUDIT_SERVICE_HOST);
    %let _identities_url=https://%sysget(SAS_IDENTITIES_SERVICE_HOST); 
  %end;
%mend;

/* Delete the base URL for the REST API. */
%macro deleteBaseUrl;
  %global _audit_url;
  %global _identities_url;
  %symdel _audit_url /nowarn;
  %symdel _identities_url /nowarn;
%mend;

/* Generate a temporary library reference name. */
%macro assignTempLibref;
  %local n;
  %let n=%sysfunc(monotonic());
  _LN%sysfunc(putn(&n, z5.))
%mend;

/* Generate a temporary file reference name. */
%macro assignTempFileref;
  %local n;
  %let n=%sysfunc(monotonic());
  _FN%sysfunc(putn(&n, z5.))
%mend;

/* Generate a temporary member name. */
%macro assignTempMemberName;
  %local n;
  %let n=%sysfunc(monotonic());
  _DN%sysfunc(putn(&n, z5.))
%mend;

/* Get a list of users. */
%macro userList(out=work.userList, limit=5000, debug=0);
  %global rc _name;
  %local lib flr flag start tmp;

  %let rc=1;
  %let lib=%assignTempLibref;
  %let flr=%assignTempFileref;
  %let tmp=%assignTempMemberName;
  filename &flr "/tmp/user.json";

  %let flag=1;
  %let start=0;

  %do %while(&flag=1);

    proc http url="&_identities_url/identities/users" out=&flr
      query=("limit"="&limit" "start"="&start") oauth_bearer=sas_services;
      headers 'Accept'='application/json';
    run;
    %if &syserr^=0 %then %goto exit;
  
    %if &SYS_PROCHTTP_STATUS_CODE. eq 200 %then %do;
      libname &lib json fileref=&flr;
      %if &syslibrc^=0 %then %goto exit;
  
      data &tmp(compress=no);
        length id name $256;
        length providerId $16;
        length description $512;
        length state $16;
        set &lib..items;
        keep id name description state;
        rename id=userId name=userName;
      run;
      %if &syserr^=0 %then %goto exit;

      %if &start=0 %then %do;
        data &out(compress=no);
          set &tmp;
        run;
      %end;
      %else %do;
        proc append base=&out data=&tmp;
        run;
      %end;
      %if &syserr^=0 %then %goto exit;

      %let obs=0;
      data _null_;
        set &lib..links(where=(rel eq 'next')) nobs=obs;
        call symputx('obs', compress(put(obs, best.)), 'L');
      run;
      %if &syserr^=0 %then %goto exit;

      %if &obs=0 %then %do;
        %let flag=0;
        proc sort data=&out;
          by userId;
        run;
        %if &syserr^=0 %then %goto exit;
        %let rc=0;
      %end;
      libname &lib clear;
      %let start=%eval(&start+&limit);
    %end;
    %else %do;
      %put ERROR: &=SYS_PROCHTTP_STATUS_CODE.;
      %goto exit;
    %end;

  %end;

  proc datasets lib=work nolist nowarn;
    delete &tmp;
  quit;
  filename &flr clear;

%exit:
  %if &debug=1 %then %put DEBUG: userList(&=out, &=limit, &=debug) &=rc;
%mend;


/* Argument dt: Pass the serial value (seconds) of a SAS datetime as a string. */
%macro _convSerial2Str(dt);
  %sysfunc(putn(%sysfunc(inputn(&dt, BEST32.)),E8601DT26.3))Z
%mend;

/* Extract audit records for the specified period to retain the user's last login history. */
%macro getAuditRecord(from=, to=, out=, limit=1000, debug=0);
  %global rc;
  %let rc=1;
  %local range last count flag lib flr tmp count next fetch;

  %let lib=%assignTempLibref;
  %let flr=%assignTempFileref;
  %let tmp=%assignTempMemberName;
  %let flag=1;
  %let last=;

  /* Assign temporary faile */
  filename &flr "/tmp/getAuditRecord.json";
  %if &syserr^=0 %then %goto exit;

  /* Check arguments. */
  %if %length(&from)=0 | %length(&to)=0 | %length(&out)=0 %then %goto exit;

  /* Retrieve the audit history repeatedly. */
  %let last=&from;
  %let fetch=0;
  %do %while (&flag=1);

    %let range="ge(timeStamp,'&last'),lt(timeStamp,'&to')";
    %let range=%qsysfunc(dequote(%superq(range)));

    proc http url="&_audit_url/audit/entries" out=&flr
      query=(
      "start"="0"
      "limit"="&limit"
      "filter"="and(in(action,'login','SessionDestroyed'),eq(state,'success'),&range)"
      "sortBy"="timeStamp"
      )
      oauth_bearer=sas_services;
      headers 'Accept'='application/json';
    run;

    /* When PROC HTTP exits normally */
    %if &syserr=0 %then %do;

      /* When the HTTP status is normal */
      %if &SYS_PROCHTTP_STATUS_CODE. eq 200 %then %do;

        libname &lib json fileref=&flr;
        /* When LIBNAME statement exits normally */
        %if &syslibrc=0 %then %do;

          /* Check if the “action” variable exists in ITEMS */
          proc sql noprint;
            select count(*) into: count from sashelp.vcolumn
            where libname="&lib" and memname="ITEMS" and lowcase(name)="action";
          quit;

          /* If no audit records exist, return an empty result. */
          %if &count=0 %then %do;

            data &out(compress=no);
              length userId timestamp action application state type $32;
              stop;
            run;
            %let rc=0;
            %let flag=0;

          %end;
          /* If audit records exist, save the last action for each user in the output results. */
          %else %if &count>0 %then %do;

            data &tmp(rename=(user=userId));
              length user timestamp action application state type $32;
              set &lib..items(keep=action application state type user timestamp);
            run;
          
            %if &fetch=1 %then %do;
              data &out;
                set &tmp;
              run;
            %end;
            %else %do;
              proc append base=&out data=&tmp;
              run;
            %end;

            proc sql noprint;
              select max(timeStamp) into: last from &out;
            quit;
            %let last=%sysfunc(trim(&last));

            /* Check if there is a link to the next page */
            proc sql noprint;
              select count(*) into: next from &lib..links where rel='next';
            quit;

            /* If LINKS cannot find the next page, it aggregates the results. */
            %if &next=0 %then %do;
              proc sort data=&out;
                by userId descending timestamp;
              run;
              %if &syserr^=0 %then %goto exit;
              %let flag=0;
              %let rc=0;
            %end;

          %end;

          %let fetch=%eval(&fetch+1);
          libname &lib clear;

        %end;
        %else %do;
          %put ERROR: libname &lib &=syslibrc;
          %let flag=0;
        %end;
      %end;
      %else %do;
        %put ERROR: PROC HTTP &=SYS_PROCHTTP_STATUS_CODE;
        %let flag=0;
      %end;
    %end;
    %else %do;
      %put ERROR: PROC HTTP &=syserr;
      %let flag=0;
    %end;
  %end;

%exit:
  filename &flr clear;
  proc datasets lib=work nolist nowarn;
    delete &tmp;
  quit;
  %if &debug=1 %then %put DEBUG: getAuditRecord(&=from, &=to, &=out, &=limit, &=debug) &=rc;
%mend;

/* Retrieve the most recent login and logoff records from AUDIT information. */
%macro auditList(out=work.auditList, dt=, days=100, debug=0);
  %global rc;
  %let rc=1;

  %local lib fref flag from to count limit tmp;
  %local /readonly step=7;
  %let lib=%assignTempLibref;
  %let flr=%assignTempFileref;
  %let tmp=%assignTempMemberName;
  filename &flr "/tmp/audit.json";
  %let flag=1;
  %let count=0;

  /* If the datetime are omitted, set the value using a function. */
  %if %length(&dt)=0 %then %let dt=%sysfunc(datetime());

  /* Determine the start and end dates for obtaining the audit history. */
  data _null_;
    dt=int(&dt);
    utc1=(dt-tzoneoff(dt))-(&days*3600*24);
    call symputx("from", compress(put(utc1, best.)));
    utc2=dt-tzoneoff(dt);
    call symputx("to", compress(put(utc2, best.)));
    limit=&step*3600*24;
    call symputx("limit", compress(put(limit, best.)));
  run;
  %if &syserr^=0 %then %return;

  %let count=0;

  %do %while (&from < &to);
    %if %eval(&from+&limit)<&to %then %do;
      %let dt1=&from;
      %let dt2=%eval(&from+&limit);
    %end;
    %else %do;
      %let dt1=&from;
      %let dt2=&to;
    %end;

    %let dt1=%_convSerial2Str(&dt1);
    %let dt2=%_convSerial2Str(&dt2);

    %getAuditRecord(from=&dt1, to=&dt2, out=&tmp, debug=&debug);
    %if &rc^=0 %then %do;
      %put ERROR: getAuditRecord &=rc;
      %return;
    %end;

    %if &count=0 %then %do;
      data &out;
        set &tmp;
      run;
    %end;
    %else %do;
      proc append base=&out data=&tmp;
      run;
    %end;

    %let from=%eval(&from+&limit);
    %let count=%eval(&count+1);
  %end;

  proc sort data=&out;
    by userId descending timestamp;
  run;

  proc sort data=&out nodupkey;
    by userId;
  run;

  %let rc=0;

%exit:
  proc datasets lib=work nolist nowarn;
    delete &tmp;
  quit;
  %if &debug=1 %then %put DEBUG: auditList(&=out, &=dt, &=days, &=debug) &=rc;
%mend;

/* Export login data to a CSV file. */
%macro saveLastLog(data=, lib=, dt=, debug=0);
  %global rc;
  %let rc=1;
  %local ymd dsn obs notes;

  /* If the datetime are omitted, set the value using a function. */
  %if %length(&dt)=0 %then %let dt=%sysfunc(datetime());

  %let ymd=%sysfunc(putn(&dt, b8601dt.));
  %let ymd=%substr(&ymd, 1, 8);
  %let dsn=%upcase(&lib).LOGON_&ymd;

  data &dsn;
    set &data end=flag nobs=obs;
    if flag then call symput('count', compress(put(obs,best.)));
  run;
  %if &syserr^=0 %then %goto exit;
  %let rc=0;

  %let notes=%sysfunc(GETOPTION(notes));
  options notes;
  %put NOTE: Dataset &dsn has been created (obs=&count);
  options &notes;

%exit:
  %if &debug=1 %then %put DEBUG: saveLastLog(&=data, &=lib, &=dt. &=debug) &=rc;
%mend;

/* Read the CSV files containing login information located in the directory。 */
%macro readLogonList(lib=, out=, debug=0);
  %global rc;
  %let rc=1;

  /* Check arguments. */
  %if %length(&lib)=0 %then %do;
    %put ERROR: Argument lib is missing.;
    %goto exit;
  %end;
  %if %superq(out)= %then %do;
    %put ERROR: Arrument out is missing.;
    %goto exit;
  %end;

  /* Confirmation of Target Member Presence. */
  proc sql noprint;
    select count(*) into :n
    from dictionary.tables
    where libname = upcase("&lib") and memtype = 'DATA' and memname like 'LOGON_20%';
  quit;

  %if &n=0 %then %do;
    %put WARNING: No dataset starting with LOGON_ was found in &lib.;
    %goto exit;
  %end;

  /* Concatenate all datasets starting with LOGON_. */
  data &out;
    set &lib..logon_20: indsname=_src;
    length source $256;
    source = _src;
    drop _src source;
  run;

  proc sort data=&out;
    by userId descending timestamp;
  run;

  proc sort data=&out nodupkey;
    by userId;
  run;

  %if &syserr ne 0 %then %do;
    %put ERROR: Failed to concatenate datasets starting with LOGON_ (&=syserr).;
  %end;
  %else %do;
    %put NOTE: The datasets were combined and output to &out..;
    %let rc=0;
  %end;

%exit:
  %if &debug=1 %then %put DEBUG: readLogonList(&=lib, &=out, &=debug) &=rc;
%mend;

/* Merge user list and login information. */
%macro mergeUserList(user=, logon=, dt=, out=, debug=0);
  %global rc;
  %let rc=1;

  /* If the datetime are omitted, set the value using a function. */
  %if %length(&dt)=0 %then %let dt=%sysfunc(datetime());

  proc sort data=&user;
    by userId;
  run;
  %if &syserr^=0 %then %goto exit;
  
  proc sort data=&logon;
    by userId;
  run;
  %if &syserr^=0 %then %goto exit;
  
  data &out;
    merge &user(in=a) &logon(in=b drop=state type);
    by userId;
  run;
  %if &syserr^=0 %then %goto exit;

  data &out;
    set &out;
    length utc_dt utc_now days 8;
  
    if not missing(timestamp) then do;
      /* Calculate the number of days since the last login. */
      utc_dt=input(compress(timestamp, 'Z'), e8601dt26.3);
      utc_now=&dt-tzoneoff();
      days=int((utc_now - utc_dt) / 86400);
    end;
    drop utc_dt utc_now;
  run;
  %if &syserr^=0 %then %goto exit;

  %let rc=0;
%exit:
  %if &debug=1 %then %put DEBUG: mergeUserList(&=user, &=logon, &=dt, &=out, &=debug) &=rc;
%mend;

/* Purge old datasets containing saved login history. */
%macro purgeLogonHistory(lib=, keep=7, debug=0);
  %global rc;
  %let rc=1;

  %local mem dsn nobs tmp;
  %let mem=LOGON_LIST;
  %let tmp=WORK.&mem;

  /* Search for the dataset to be deleted. */
  proc sql noprint;
    create table &tmp as
    select memname, substr(memname, 7, 8) as ymd
    from dictionary.tables
    where upcase(libname)="%upcase(&lib)" and memtype='DATA' and memname like 'LOGON_20______';
  quit;
  %if &sqlrc ne 0 %then %goto error;

  /* Check the number of records in the acquired dataset. */
  %let nobs=0;
  data _null_;
    set &tmp nobs=nobs;
    call symputx('nobs', compress(put(nobs, best.)), 'L');
    stop;
  run;
  %if &syserr^=0 %then %goto exit;

  proc sort data=&tmp;
    by descending ymd;
  run;
  %if &syserr^=0 %then %goto exit;

  data &tmp;
    set &tmp;
    no = _n_;
  run;
  %if &syserr^=0 %then %goto exit;

  %let list=;
  proc sql noprint;
    select memname into :list separated by ' ' from &tmp where no > &keep;
  quit;
  %if &sqlrc ne 0 %then %goto error;

  %if %length(&list)>0 %then %do;
    proc datasets lib=&lib nolist nowarn;
      delete &list / memtype=data;
    quit;
    %if &syserr^=0 %then %goto exit;
  %end;

  %let rc=0;

%exit:
  proc datasets lib=work nolist nowarn;
    delete &mem;
  quit;
  %if &debug=1 %then %put DEBUG: purgeLogonHistory(&=lib, &=keep, &=debug) &=rc;

%mend;

/* Check the output dataset and log the message. */
%macro noteOutputDataset(data=);
  %local lib mem dsn obs _notes;
  %let lib=%upcase(%scan(&data, 1, .));
  %let mem=%upcase(%scan(&data, 2, .));
  %let notes=%sysfunc(GETOPTION(notes));
  options nonotes;

  /* Set the two-level dataset name to a macro variable. */
  %if %length(&mem)=0 %then %do;
    %let mem=&lib;
    %let lib=WORK;
  %end;
  %let dsn=&lib..&mem;

  /* Presence Check. */
  %if %sysfunc(exist(&dsn))=0 %then %do;
    %put WARNING: Dataset &dsn not found.;
    %goto exit;
  %end;

  %let obs=0;
  data _null_;
    set &dsn nobs=obs;
    call symputx('obs', compress(put(obs, best.)));
    stop;
  run;

  options notes;
  %put NOTE: Dataset &dsn has been created (obs=&obs);
  options nonotes

%exit:
  options &notes;
%mend;

/* Create a list of logon history datasets. */
%macro logonMemberList(lib=, out=);
  %global rc;
  %let rc=1;

  data &out(compress=no);
    set sashelp.vtable(where=(libname eq "%upcase(&lib)" and memtype eq 'DATA' 
      and memname like 'LOGON_%'));
    p=prxmatch('/LOGON_\d{8}/', memname);
    len=length(memname);

    if p ne 1 or len ne 14 then delete;
    keep memname;
  run;
  %if &syserr&=0 %then %return;

  proc sort data=&out;
    by descending memname;
  run;
  %if &syserr&=0 %then %return;

  data &out(compress=no);
    set &out;
    no=_n_;
  run;
  %if &syserr&=0 %then %return;

  %let rc=0;
%mend;

/* Carete dummy logon dataset. */
%macro createEmptyLog(out=work.lastLog);
  data &out;
    length userId timestamp action application state type $32;
    stop;
  run;
%mend;

%macro readLastLog(lib=, data=, out=work.lastLog);
  %global rc;
  %let rc=1;

  %assignMemberList(data=&data, macvar=_list);
  %let n=%sysfunc(countw(%superq(_list), %str( )));
  data &out;
    set
      %do i=1 %to &n;
        &lib..%qscan(%superq(_list), &i, %str( ))
      %end;
    ;
  run;
  %if &syserr^=0 %then %return;

  proc sort data=&out;
    by userId descending timestamp;
  run;
  %if &syserr^=0 %then %return;

  proc sort data=&out nodupkey;
    by userId;
  run;
  %if &syserr^=0 %then %return;

  %let rc=0;
%mend;

/* Sort the logon history dataset in a new order and set it to a macro variable. */
%macro assignMemberList(data=, macvar=);
  %global &macvar rc;
  %let rc=1;
  proc sql noprint;
    select memname into :&macvar separated by ' ' from &data order by memname desc;
  quit;
  %if &sqlrc=0 %then %let rc=0;
%mend;

%macro appendAuditList(base=, data=);
  %global rc;
  %let rc=1;

  proc append base=&base data=&data;
  run;
  %if &syserr&=0 %then %return;

  proc sort data=&base;
    by userId descending timestamp;
  run;
  %if &syserr&=0 %then %return;

  proc sort data=&base nodupkey;
    by userId;
  run;
  %if &syserr&=0 %then %return;

  %let rc=0;
%mend;


/* A macro that matches audit logs with user information and saves the last logon date and time. */
%macro inactiveUserList(lib=work, out=work.inactive, days=60, keep=7, offset=0, notes=0, debug=0);
  %global rc;
  %let rc=1;
  %local dir _notes count dt tmp last;
  %let _notes=%sysfunc(GETOPTION(notes));
  %if &notes=0 %then %do;
    options nonotes;
  %end;
  %let tmp=%assignTempMemberName;

  /* Check arguments. */
  %let rc=%sysfunc(libref(&lib));
  %if &rc^=0 %then %do;
    %put ERROR: The library reference name &lib is not defined.;
    %let rc=1;
    %goto exit;
  %end;

  /* Store the current date and time in a macro variable. */
  %let dt=%sysfunc(datetime());
  %let dt=%sysevalf(&dt-%eval(86400*&offset));

  %defineBaseUrl;

  %userList(out=work.userList, debug=&debug);
  %if &rc^=0 %then %goto exit;

  %logonMemberList(lib=&lib, out=&tmp);
  %if &rc^=0 %then %goto exit;

  /* Check the number of datasets in the logon history. */
  %let count=0;
  data _null_;
    set &tmp nobs=obs;
    call symputx("count", compress(put(obs, best.)));
    stop;
  run;

  %if &count=0 %then %do;
    /* If there is no past login history. */
    %createEmptyLog(out=work.lastLog);
  %end;
  %else %do;
    /* If past log history exists. */
    %readLastLog(lib=&lib, data=&tmp, out=work.lastLog);

    /* Retrieve the date and time of the last observed login. */
    proc sql noprint;
      select max(timeStamp) into: last from work.lastLog;
    quit;
    %let last=%sysfunc(trim(&last));

    data _null_;
      last = input("&last", e8601dz.);
      days = ceil((&dt - last) / 86400);
      call symput("newdays", compress(put(days, 8.)));
    run;
    %if &newdays<&days %then %do;
      options notes;
      %put NOTE: Macro variable DAYS changed from &days to &newdays;
      %let days=&newdays;
      options nonotes;
    %end;
  %end;


  %auditList(out=work.auditList, dt=&dt, days=&days, debug=&debug);
  %if &rc^=0 %then %goto exit;

  %appendAuditList(base=work.auditList, data=work.lastLog);
  %if &rc^=0 %then %goto exit;

  %saveLastLog(data=work.auditList, lib=&lib, dt=&dt, debug=&debug);
  %if &rc^=0 %then %goto exit;

  %mergeUserList(user=work.userList, logon=work.auditList, dt=&dt, out=&out, debug=&debug);
  %if &rc^=0 %then %goto exit;

  %purgeLogonHistory(lib=&lib, keep=&keep, debug=&debug);
  %if &rc^=0 %then %goto exit;
  %let rc=0;

  proc datasets lib=work nolist nowarn;
    delete &tmp;
  quit;

  proc datasets lib=work nolist nowarn;
    %if &debug=0 %then %do;
      delete userList auditList lastLog;
    %end;
  quit;

%exit:
  %deleteBaseUrl;
  options notes;
  %put NOTE: inactiveUserList(&=lib, &=out, &=days, &=offset, &=notes, &=debug) &=rc;
  %if &rc=0 %then %noteOutputDataset(data=&out);
  options &_notes;
%mend;

options source;