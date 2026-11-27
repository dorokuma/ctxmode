package main

// role_guards_py_allowlist.go — strict-readonly Python allowlist lexer, parser, and evaluator.

import (
	"strings"
)

const strictReadonlyBlockLegacyScripting = true

func sroWordSet(raw string) map[string]bool {
	fields := strings.Fields(raw)
	m := make(map[string]bool, len(fields))
	for _, f := range fields {
		m[f] = true
	}
	return m
}

// Offline-generated CPython dir() member sets (non-readonly public & single-'_' private).
var sroPyNonROMembers = sroWordSet(`
	AND ARITH ATOM AWAIT BAND BOOLEAN_STATES BXOR CMP DataError DatabaseError EXPR Emax Emin Error Etiny Etop FACTOR
	FileHeader IntegrityError InterfaceError InternalError KEYWORD_ONLY MAX_N MAX_SEEK_READ MIN_READ_SIZE NAMED_EXPR
	NONSPACECRE NOT NotSupportedError OPEN_METH OPTCRE OPTCRE_NV OR OperationalError POSITIONAL_ONLY
	POSITIONAL_OR_KEYWORD POWER ProgrammingError SECTCRE SHIFT TERM TEST TUPLE VAR_KEYWORD VAR_POSITIONAL VERSION
	Warning YIELD abs absolute aclose acquire add addFilter addHandler add_argument add_argument_group
	add_mutually_exclusive_group add_note add_section add_subparsers addfile adjusted ag_await ag_code ag_frame
	ag_running append appendleft apply_defaults arguments arraysize as_integer_ratio as_posix as_tuple as_uri asend
	asname astimezone athrow autocommit backup betavariate bind bind_partial binop binop_precedence binop_rassoc
	bit_count bit_length blobopen block block_size blocksize boolop_precedence boolops braceidpattern buffer
	buffered bz2open c_contiguous callHandlers canonical capitals case_sensitive cast cell_contents
	characters_written check chmod choice choices chown clamp clear clear_flags clear_traps clock_seq
	clock_seq_hi_variant clock_seq_low close closefd cmpops co_argcount co_cellvars co_code co_consts
	co_exceptiontable co_filename co_firstlineno co_flags co_freevars co_kwonlyargcount co_lines co_linetable
	co_lnotab co_name co_names co_nlocals co_positions co_posonlyargcount co_qualname co_stacksize co_varnames
	combine commit compare compare_signal compare_total compare_total_mag compress compress_type conjugate
	connection contiguous convert_arg_line_to_args converter converters copy copy_abs copy_decimal copy_into
	copy_negate copy_sign cr_await cr_code cr_frame cr_origin cr_running cr_suspended createLock create_aggregate
	create_collation create_decimal create_decimal_from_float create_function create_gnu_header create_module
	create_pax_global_header create_pax_header create_system create_ustar_header create_version
	create_window_function critical ctime cursor cwd date debug decompress default_factory default_msec_format
	default_time_format defaults deleter delimit delimit_if delimiter dereference deserialize detach devmajor
	devminor dialect difference difference_update digest_size dims disable discard divide divide_int divmod
	do_visit_try doublequote dst emit enable_load_extension entity eof error error_leader errorlevel escapechar
	exception exec_module execute executemany executescript exit exp expand expanduser expovariate extend extendleft
	external_attr extra extract extract_version extractall extractfile extraction_filter f_back f_builtins f_code
	f_contiguous f_globals f_lasti f_lineno f_locals f_trace f_trace_lines f_trace_opcodes fatal fdel feed fetchall
	fetchmany fetchone fget fieldnames fileno fileobject fill filter findCaller find_longest_match find_module
	find_spec findall finditer findtext firstweekday flag_bits flush fma formatException formatMessage formatStack
	formatTime format_help format_map format_spec format_usage formatday formatmonth formatmonthname formatweek
	formatweekday formatweekheader formatyear fp from_bytes from_callable from_decimal from_file from_float
	from_iterable from_uri frombuf fromhex fromisocalendar fromisoformat fromkeys fromordinal fromtarfile
	fromtimestamp fromutc fset full full_match fullmatch gammavariate gauss generic_visit getChild getEffectiveLevel
	getLogger getMessage get_code get_default get_grouped_opcodes get_identifiers get_info get_matching_blocks
	get_name get_nowait get_opcodes get_precedence get_raw_docstring get_source get_token get_type_comment
	getboolean getbuffer getconfig getfirstweekday getfloat getinfo getint getlimit getmember getrandbits getroot
	getstate gettarinfo getter geturl getvalue gi_code gi_frame gi_running gi_suspended gi_yieldfrom glob guard
	gzopen handle handleError hardlink_to hasHandlers has_header has_option has_section header_offset home idpattern
	ignore_zeros in_transaction indices info inode insert interleave internal_attr interrupt intersection
	intersection_update isEnabledFor is_block_device is_canonical is_char_device is_fifo is_finite is_infinite
	is_integer is_junction is_mount is_nan is_normal is_package is_qnan is_relative_to is_reserved is_safe is_signed
	is_snan is_socket is_subnormal is_valid is_zero isatty isblk ischr isdev isdir isdisjoint isfifo isfile islnk
	isocalendar isolation_level isoweekday isreadable isrecursive isreg issparse issubset issuperset issym
	items_view itemsize iter_unpack iterdir iterdump iterfind itermonthdates itermonthdays itermonthdays2
	itermonthdays3 itermonthdays4 itertext iterweekdays joinpath kwarg kwargs lchmod limit_denominator line_num
	lineterminator link_to linkpath list ln load_extension load_module log log10 logb logical_and logical_invert
	logical_or logical_xor lognormvariate lstat makeRecord make_file make_table makedev makedir makeelement makefifo
	makefile makelink maketrans makeunknown manager mapping match max_mag maxlen maybe_newline min_mag minus mkdir
	module_repr monthdatescalendar monthdays2calendar monthdayscalendar move move_into move_to_end mro multiply
	myfileobj n_fields n_sequence_fields n_unnamed_fields nbytes ndim needs_input new_child next next_minus
	next_plus next_toward normalize normalvariate now number_class obj open options optionxform orig_filename owner
	pack pack_into paretovariate parse parse_args parse_intermixed_args parse_known_args parse_known_intermixed_args
	parser peek pformat pi plus pop pop_source popitem popleft power pprint prec print_help print_usage printdir
	prmonth process processor prweek pryear punctuation_chars push_source push_token put put_nowait qsize quantize
	quick_ratio quotechar quoting radix randbytes randint random randrange ratio raw read read1 read_dict read_file
	read_string read_token readable readall readfp readinto readinto1 readline readlines readlink readonly
	real_quick_ratio reconfigure register relative_to remainder remainder_near remove removeFilter removeHandler
	remove_option remove_section rename replace require_parens reserved resolve rest reverse rewind rglob rmdir
	rollback rotate rounding row_factory s safe_substitute same_quantum samefile sample scaleb scanner search
	sections seed seek seekable send sentence_end_re serialize set setFormatter setLevel setLogRecordFactory
	setLoggerClass setStream set_authorizer set_defaults set_name set_precedence set_progress_handler set_seq1
	set_seq2 set_seqs set_trace_callback setconfig setdefault setfirstweekday setinputsizes setlimit setoutputsize
	setpassword setstate setter shape shift shuffle signature skipinitialspace sniff sort sourcehook span sparse
	sqrt stat stop strftime strides strptime sub subn suboffsets substitute subtract symlink_to symmetric_difference
	symmetric_difference_update tarfile tarinfo taropen task_done tb_frame tb_lasti tb_lineno tb_next tell
	terminator testzip text_factory throw time time_hi_version time_low time_mid timestamp timetuple timetz to_bytes
	to_eng_string to_integral to_integral_exact to_integral_value to_sci_string tobuf tobytes today tolist toordinal
	toreadonly total_changes total_seconds touch translate traverse triangular truncate type_params tzname
	unconsumed_tail unicode_whitespace_trans uniform union unlink unop unop_precedence unpack unpack_from
	unused_data update usesTime utcfromtimestamp utcnow utcoffset utctimetuple utime vararg visit visit_AnnAssign
	visit_Assert visit_Assign visit_AsyncFor visit_AsyncFunctionDef visit_AsyncWith visit_Attribute visit_AugAssign
	visit_Await visit_BinOp visit_BoolOp visit_Break visit_Call visit_ClassDef visit_Compare visit_Constant
	visit_Continue visit_Delete visit_Dict visit_DictComp visit_Ellipsis visit_ExceptHandler visit_Expr visit_For
	visit_FormattedValue visit_FunctionDef visit_FunctionType visit_GeneratorExp visit_Global visit_If visit_IfExp
	visit_Import visit_ImportFrom visit_JoinedStr visit_Lambda visit_List visit_ListComp visit_Match visit_MatchAs
	visit_MatchClass visit_MatchMapping visit_MatchOr visit_MatchSequence visit_MatchSingleton visit_MatchStar
	visit_MatchValue visit_Module visit_Name visit_NamedExpr visit_Nonlocal visit_Pass visit_Raise visit_Return
	visit_Set visit_SetComp visit_Slice visit_Starred visit_Subscript visit_Try visit_TryStar visit_Tuple
	visit_UnaryOp visit_While visit_With visit_Yield visit_YieldFrom visit_alias visit_arg visit_arguments
	visit_comprehension visit_keyword visit_match_case visit_withitem volume vonmisesvariate walk warn warning
	weekday weibullvariate with_name with_segments with_stem with_suffix with_traceback wordsep_re wordsep_simple_re
	wrap writable write write_bytes write_c14n write_text write_through writelines writestr xzopen yeardatescalendar
	yeardays2calendar yeardayscalendar
`)

// Offline-generated CPython dir() member sets (non-readonly public & single-'_' private).
var sroPyAllPrivMembers = sroWordSet(`
	_ _ActionsContainer _AppendAction _AppendConstAction _ArgumentGroup _AttributeHolder _CD64_CREATE_VERSION
	_CD64_DIRECTORY_RECSIZE _CD64_DIRECTORY_SIZE _CD64_DISK_NUMBER _CD64_DISK_NUMBER_START _CD64_EXTRACT_VERSION
	_CD64_NUMBER_ENTRIES_THIS_DISK _CD64_NUMBER_ENTRIES_TOTAL _CD64_OFFSET_START_CENTDIR _CD64_SIGNATURE
	_CD_COMMENT_LENGTH _CD_COMPRESSED_SIZE _CD_COMPRESS_TYPE _CD_CRC _CD_CREATE_SYSTEM _CD_CREATE_VERSION
	_CD_DATE _CD_DISK_NUMBER_START _CD_EXTERNAL_FILE_ATTRIBUTES _CD_EXTRACT_SYSTEM _CD_EXTRACT_VERSION
	_CD_EXTRA_FIELD_LENGTH _CD_FILENAME_LENGTH _CD_FLAG_BITS _CD_INTERNAL_FILE_ATTRIBUTES
	_CD_LOCAL_HEADER_OFFSET _CD_SIGNATURE _CD_TIME _CD_UNCOMPRESSED_SIZE _CHUNK_SIZE _ChainMap _CountAction
	_DD_SIGNATURE _DEFAULT_INTERPOLATION _ECD_COMMENT _ECD_COMMENT_SIZE _ECD_DISK_NUMBER _ECD_DISK_START
	_ECD_ENTRIES_THIS_DISK _ECD_ENTRIES_TOTAL _ECD_LOCATION _ECD_OFFSET _ECD_SIGNATURE _ECD_SIZE
	_EXTRA_FIELD_STRUCT _Element_Py _EndRecData _EndRecData64 _Environ _ExtendAction _FH_COMPRESSED_SIZE
	_FH_COMPRESSION_METHOD _FH_CRC _FH_EXTRACT_SYSTEM _FH_EXTRACT_VERSION _FH_EXTRA_FIELD_LENGTH
	_FH_FILENAME_LENGTH _FH_GENERAL_PURPOSE_FLAG_BITS _FH_LAST_MOD_DATE _FH_LAST_MOD_TIME _FH_SIGNATURE
	_FH_UNCOMPRESSED_SIZE _FileInFile _Flavour _HelpAction _IGNORED_ERRNOS _IGNORED_WINERRORS _ListDataStream
	_LowLevelFile _MASK_COMPRESSED_PATCH _MASK_COMPRESS_OPTION_1 _MASK_ENCRYPTED _MASK_STRONG_ENCRYPTION
	_MASK_USE_DATA_DESCRIPTOR _MASK_UTF_FILENAME _MutableMapping__marker _MutuallyExclusiveGroup _OPT_NV_TMPL
	_OPT_TMPL _ORIGIN _PathParents _Path__repr _PosixFlavour _PreciseSelector _RealGetContents
	_RecursiveWildcardSelector _SECT_TMPL _STYLES _Selector _SequenceMatcher__chain_b _SharedFile _StderrHandler
	_StoreAction _StoreConstAction _StoreFalseAction _StoreTrueAction _Stream _StreamProxy _SubParsersAction
	_Tellable _TerminatingSelector _UNRECOGNIZED_ARGS_ATTR _UNSET _UserList__cast _VersionAction
	_WINERROR_CANT_RESOLVE_FILENAME _WINERROR_INVALID_NAME _WINERROR_NOT_READY _WildcardSelector _WindowsFlavour
	_ZipDecrypter _ZipWriteFile _abc_impl _acquireLock _add _addHandlerRef _add_action _add_container_actions
	_after_at_fork_child_reinit_locks _ancestry _annotation _apply _apply_pax_info _asdict _at_fork_reinit
	_at_fork_reinit_lock_weakset _attributes _base_executable _bind _blksize _block _bound_arguments_cls
	_cached_cparts _check _checkClosed _checkLevel _checkReadable _checkSeekable _checkWritable _check_can_read
	_check_can_seek _check_can_write _check_compression _check_conflict _check_methods _check_not_closed
	_check_value _check_zipfile _clear_cache _clear_type_cache _co_code_adaptive _collect_lines _compresslevel
	_convert_flags _convert_to_boolean _copy_items _cparts _crctable _create_gnu_long_header _create_header
	_create_pax_generic_header _create_payload _current _current_exceptions _current_frames _dbg _dealloc_warn
	_debugmallocstats _decodeExtra _decode_pax_field _dedupe _default _defaultFormatter _defaultLastResort
	_default_dict _default_prefix _denominator _difference _dispatch _div _divmod _drv _dump
	_encodeFilenameFlags _encoded_counterpart _end_offset _escape_attrib _escape_attrib_c14n _escape_attrib_html
	_escape_cdata _escape_cdata_c14n _execvpe _exists _exit _extract_member _extract_text_encoding _fancy_helper
	_fancy_replace _field_defaults _fields _file_template _finalizing _find_link_target _fix_sentence_endings
	_fixupChildren _fixupParents _flavour _floordiv _for_helper _format _format_dict_items _format_items
	_format_line _format_namespace_items _format_parsed_parts _fpclose _framework _from_parsed_parts _from_parts
	_frombuf _fromtarfile _fspath _function_helper _fwalk _gen_crc _get _get_action_name _get_args
	_get_compressor _get_conv _get_decompressor _get_exports_list _get_formatter _get_handler _get_kwargs
	_get_nargs_pattern _get_option_tuples _get_optional_actions _get_optional_kwargs _get_positional_actions
	_get_positional_kwargs _get_sep _get_value _get_values _get_writer _getframe _getmember _getquickenedcount
	_git _guess_delimiter _guess_quote_and_delimiter _handle_conflict_error _handle_conflict_resolve
	_handle_error _handle_long_word _handlerList _handlers _hash _hash_basis _header_length_prefix_re _hmac
	_home _hostinfo _ignore_error _init _init_decrypter _init_hmac _init_old _init_write _inner _invalid _io
	_is_child _is_internal_frame _is_wildcard_pattern _join_multiline_values _joinrealpath _keep_positive _kind
	_legend _levelToName _line_wrapper _link_target _load _lock _log _logRecordFactory _loggerClass
	_looks_like_prefix_name _make _make_child _make_child_relpath _make_prefix _make_selector _match_argument
	_match_arguments_partial _mod _mul _munge_whitespace _name _nameToLevel _namespace_map _namespaces _next
	_numerator _open _open_to_write _operator_fallbacks _options _os _outer _parameter_cls _parameters _parents
	_parse_args _parse_known_args _parse_optional _parse_whole _parts _path_normpath _plain_replace
	_pop_action_class _posix_flavour _posix_split_name _pparts _pprint_bytearray _pprint_bytes _pprint_chain_map
	_pprint_counter _pprint_dataclass _pprint_default_dict _pprint_deque _pprint_dict _pprint_list
	_pprint_mappingproxy _pprint_ordered_dict _pprint_set _pprint_simplenamespace _pprint_str _pprint_tuple
	_pprint_user_dict _pprint_user_list _pprint_user_string _print_message _proc_builtin _proc_gnulong
	_proc_gnusparse_00 _proc_gnusparse_01 _proc_gnusparse_10 _proc_member _proc_pax _proc_sparse _put _qformat
	_qsize _raise_serialization_error _randbelow _randbelow_with_getrandbits _randbelow_without_getrandbits
	_raw_time _re _read _read1 _read2 _read_args_from_files _read_defaults _register_at_fork_reinit_lock
	_registry_get _releaseLock _removeHandlerRef _remove_action _replace _repr _return_annotation _richcmp _root
	_safe_print _safe_repr _sanitize_windows_name _scandir _serialize _serialize_html _serialize_text
	_serialize_xml _set_factories _setevents _setroot _showwarning _signature _sparse_structs _spawnvef _split
	_split_chunks _split_line _srcfile _startTime _stdlib_dir _str _str_formatter _str_literal_helper
	_strip_extra _styles _sub _sys _tab_newline_replace _table_template _unify_values _update_crc _userinfo
	_valid _validate _validate_value_types _varname_from_oparg _varpattern _varsub _varsubb _walk
	_warnings_showwarning _windows_flavour _windows_illegal_name_trans_table _wrap_chunks _wrap_close
	_write_constant _write_docstring _write_docstring_and_traverse_body _write_end_record _write_fstring_inner
	_write_gzip_header _write_section _write_str_avoiding_backslashes _writecheck _xoptions
`)

var sroPyUncalledMeths = sroWordSet(`
	capitalize casefold center count decode encode endswith expandtabs find hex
	index isalnum isalpha isascii isdecimal isdigit isidentifier islower isnumeric
	isprintable isspace istitle isupper join ljust lower lstrip partition
	removeprefix removesuffix rfind rindex rjust rpartition rsplit rstrip split
	splitlines startswith strip swapcase title upper zfill
	get keys values items most_common elements total
	exists is_dir is_file is_symlink is_absolute namelist getnames getmembers
	infolist read_text read_bytes hexdigest digest isoformat group groups groupdict
	format_help format_usage
`)

var sroPyDirectMeths = func() map[string]bool {
	m := sroWordSet(`
		format format_map maketrans translate
		add append clear difference difference_update discard extend extendleft
		intersection intersection_update isdisjoint issubset issuperset move_to_end
		pop popitem popleft remove reverse rotate setdefault sort subtract
		symmetric_difference symmetric_difference_update union update
		as_integer_ratio bit_count bit_length conjugate from_bytes to_bytes
		close expanduser extractfile fetchall fetchmany fetchone fileno findall
		finditer findtext fullmatch get_default getboolean getfloat getinfo getint
		getmember getroot getvalue glob has_option has_section inode
		is_block_device is_char_device is_fifo is_mount is_relative_to is_reserved
		is_socket isatty isocalendar isdir isfile islnk isreg issym iter iterdir
		iterdump iterfind itertext joinpath lstat match options parse_args
		parse_known_args peek pformat pprint read read_dict read_file read_string
		readable readlink readline readlines relative_to resolve rglob samefile
		search sections seek seekable span start end stat strftime sub subn tell
		testzip timetuple timestamp toordinal utctimetuple weekday isoweekday
		with_name with_stem with_suffix as_posix as_uri
		now today utcnow fromisoformat fromtimestamp utcfromtimestamp strptime
		combine fromordinal
		add_argument add_argument_group add_mutually_exclusive_group
		addHandler setFormatter setLevel debug info warning warn error critical
		exception cursor owner
	`)
	for k := range sroPyUncalledMeths {
		m[k] = true
	}
	return m
}()

var sroPyDataAttrs = sroWordSet(`
	name stem suffix suffixes parent parents parts anchor drive root
	st_mode st_ino st_dev st_nlink st_uid st_gid st_size
	st_atime st_mtime st_ctime st_atime_ns st_mtime_ns st_ctime_ns
	st_blocks st_blksize st_rdev path
	year month day hour minute second microsecond tzinfo fold
	days seconds microseconds min max resolution utc
	tm_year tm_mon tm_mday tm_hour tm_min tm_sec tm_wday tm_yday tm_isdst tm_zone tm_gmtoff
	pattern flags groupindex pos endpos lastindex lastgroup re string regs
	lineno col_offset end_lineno end_col_offset id attr arg value target targets
	body orelse finalbody handlers func args keywords decorator_list bases
	names module level elts ops comparators left right op operand test
	iter ifs generators annotation returns type_comment ctx slice step
	msg exc cause context_expr optional_vars is_async n
	filename file_size compress_size date_time CRC comment
	size mtime mode type linkname uid gid uname gname chksum offset offset_data pax_headers
	tag text tail attrib data
	scheme netloc params query fragment username password hostname port
	system node release version machine
	errno strerror filename2 returncode code
	description rowcount lastrowid
	real imag numerator denominator
	closed encoding errors newlines line_buffering
	int bytes bytes_le fields urn variant
	format start end line lines columns exact_type
	parameters return_annotation default kind empty fp
`)

var sroPyAllPubMembers = func() map[string]bool {
	m := make(map[string]bool, len(sroPyNonROMembers)+len(sroPyDirectMeths)+len(sroPyDataAttrs))
	for k := range sroPyNonROMembers {
		m[k] = true
	}
	for k := range sroPyDirectMeths {
		m[k] = true
	}
	for k := range sroPyDataAttrs {
		m[k] = true
	}
	return m
}()

type sroPyExportKind uint8

const (
	sroPyExpConst sroPyExportKind = iota
	sroPyExpCall
	sroPyExpValueCls
	sroPyExpSubmod
)

func sroPyExports(calls, valCls, consts, submods string) map[string]sroPyExportKind {
	m := make(map[string]sroPyExportKind)
	for _, w := range strings.Fields(calls) {
		m[w] = sroPyExpCall
	}
	for _, w := range strings.Fields(valCls) {
		m[w] = sroPyExpValueCls
	}
	for _, w := range strings.Fields(consts) {
		m[w] = sroPyExpConst
	}
	for _, w := range strings.Fields(submods) {
		m[w] = sroPyExpSubmod
	}
	return m
}

var sroPyModExports = map[string]map[string]sroPyExportKind{
	"argparse":              sroPyExports("ArgumentParser Namespace", "", "SUPPRESS OPTIONAL ZERO_OR_MORE ONE_OR_MORE REMAINDER", ""),
	"ast":                   sroPyExports("parse literal_eval walk iter_fields iter_child_nodes get_docstring get_source_segment unparse dump AST Module FunctionDef AsyncFunctionDef ClassDef Import ImportFrom Call Name Attribute Constant Assign AnnAssign AugAssign Return Expr", "NodeVisitor", "", ""),
	"base64":                sroPyExports("b64encode b64decode standard_b64encode standard_b64decode urlsafe_b64encode urlsafe_b64decode b32encode b32decode b16encode b16decode", "", "", ""),
	"binascii":              sroPyExports("hexlify unhexlify b2a_hex a2b_hex b2a_base64 a2b_base64 crc32", "", "", ""),
	"bisect":                sroPyExports("bisect bisect_left bisect_right", "", "", ""),
	"bz2":                   sroPyExports("open BZ2File compress decompress", "", "", ""),
	"calendar":              sroPyExports("isleap leapdays weekday monthrange month timegm", "", "day_name month_name", ""),
	"collections":           sroPyExports("namedtuple", "Counter defaultdict OrderedDict deque ChainMap", "", "abc"),
	"collections.abc":       sroPyExports("Iterable Iterator Mapping Sequence Set Callable", "", "", ""),
	"configparser":          sroPyExports("ConfigParser RawConfigParser", "", "", ""),
	"copy":                  sroPyExports("copy deepcopy", "", "", ""),
	"csv":                   sroPyExports("reader DictReader Sniffer field_size_limit", "", "QUOTE_ALL QUOTE_MINIMAL QUOTE_NONNUMERIC QUOTE_NONE", ""),
	"dataclasses":           sroPyExports("dataclass field fields asdict astuple is_dataclass replace", "", "KW_ONLY MISSING", ""),
	"datetime":              sroPyExports("", "date time datetime timedelta timezone", "MINYEAR MAXYEAR UTC", ""),
	"decimal":               sroPyExports("getcontext localcontext", "Decimal", "", ""),
	"difflib":               sroPyExports("unified_diff context_diff ndiff get_close_matches SequenceMatcher", "", "", ""),
	"enum":                  sroPyExports("Enum IntEnum StrEnum Flag IntFlag auto unique", "", "", ""),
	"errno":                 sroPyExports("", "", "ENOENT EACCES EEXIST EINTR EINVAL EIO EISDIR ENOTDIR EPERM errorcode", ""),
	"fnmatch":               sroPyExports("fnmatch fnmatchcase filter translate", "", "", ""),
	"fractions":             sroPyExports("", "Fraction", "", ""),
	"functools":             sroPyExports("reduce lru_cache cache cmp_to_key partial", "", "", ""),
	"glob":                  sroPyExports("glob iglob escape", "", "", ""),
	"gzip":                  sroPyExports("open GzipFile compress decompress", "", "", ""),
	"hashlib":               sroPyExports("md5 sha1 sha224 sha256 sha384 sha512 blake2b blake2s sha3_256 sha3_512 new file_digest pbkdf2_hmac", "", "algorithms_guaranteed", ""),
	"heapq":                 sroPyExports("heappush heappop heapify nlargest nsmallest merge", "", "", ""),
	"hmac":                  sroPyExports("new digest compare_digest", "", "", ""),
	"html":                  sroPyExports("escape unescape", "", "", ""),
	"io":                    sroPyExports("StringIO BytesIO FileIO open TextIOWrapper BufferedReader", "", "DEFAULT_BUFFER_SIZE", ""),
	"itertools":             sroPyExports("combinations combinations_with_replacement compress count cycle dropwhile filterfalse groupby islice pairwise permutations product repeat starmap takewhile tee zip_longest accumulate batched", "chain", "", ""),
	"json":                  sroPyExports("loads load dumps dump JSONDecodeError", "", "", ""),
	"keyword":               sroPyExports("iskeyword issoftkeyword", "", "kwlist softkwlist", ""),
	"linecache":             sroPyExports("getline getlines", "", "", ""),
	"logging":               sroPyExports("getLogger basicConfig StreamHandler NullHandler Formatter Filter LoggerAdapter debug info warning warn error critical exception log disable getLevelName", "", "DEBUG INFO WARNING WARN ERROR CRITICAL NOTSET", ""),
	"lzma":                  sroPyExports("open LZMAFile compress decompress", "", "", ""),
	"math":                  sroPyExports("ceil floor trunc fabs factorial fmod fsum gcd lcm isclose isfinite isinf isnan isqrt prod exp log log2 log10 pow sqrt sin cos tan asin acos atan atan2 degrees radians hypot", "", "pi e tau inf nan", ""),
	"numbers":               sroPyExports("Number Complex Real Rational Integral", "", "", ""),
	"operator":              sroPyExports("add sub mul truediv floordiv mod neg pos abs eq ne lt le gt ge not_ truth is_ is_not and_ or_ xor index contains countOf indexOf", "", "", ""),
	"os":                    sroPyExports("getcwd listdir scandir walk stat lstat readlink access getenv cpu_count getpid getppid fspath strerror", "", "environ sep altsep extsep pathsep linesep curdir pardir devnull name F_OK R_OK W_OK X_OK", "path"),
	"os.path":               sroPyExports("abspath basename commonpath commonprefix dirname exists expanduser expandvars getatime getctime getmtime getsize isabs isdir isfile islink ismount join lexists normcase normpath realpath relpath samefile split splitdrive splitext", "", "sep pathsep extsep curdir pardir devnull", ""),
	"pathlib":               sroPyExports("Path PurePath PosixPath PurePosixPath WindowsPath PureWindowsPath", "", "", ""),
	"platform":              sroPyExports("system node release version machine uname python_version python_version_tuple python_implementation python_compiler platform", "", "", ""),
	"pprint":                sroPyExports("pprint pformat pp isreadable isrecursive saferepr PrettyPrinter", "", "", ""),
	"random":                sroPyExports("Random seed random uniform randint randrange choice choices sample shuffle", "", "", ""),
	"re":                    sroPyExports("compile search match fullmatch split findall finditer sub subn escape Pattern Match error", "", "ASCII A IGNORECASE I MULTILINE M DOTALL S VERBOSE X", ""),
	"shlex":                 sroPyExports("split quote join", "", "", ""),
	"sqlite3":               sroPyExports("connect Error DatabaseError OperationalError IntegrityError ProgrammingError", "", "Row sqlite_version sqlite_version_info", ""),
	"stat":                  sroPyExports("S_ISDIR S_ISCHR S_ISBLK S_ISREG S_ISFIFO S_ISLNK S_ISSOCK S_IMODE S_IFMT filemode", "", "ST_MODE ST_SIZE ST_MTIME", ""),
	"statistics":            sroPyExports("mean fmean median median_low median_high mode multimode pstdev pvariance stdev variance quantiles", "", "", ""),
	"string":                sroPyExports("Template capwords", "", "ascii_letters ascii_lowercase ascii_uppercase digits hexdigits octdigits punctuation printable whitespace", ""),
	"struct":                sroPyExports("pack unpack unpack_from iter_unpack calcsize Struct error", "", "", ""),
	"sys":                   sroPyExports("exit getsizeof getrecursionlimit", "", "stdin stdout stderr argv path version version_info platform maxsize byteorder executable prefix", ""),
	"tarfile":               sroPyExports("open TarFile is_tarfile TarError ReadError", "", "", ""),
	"textwrap":              sroPyExports("wrap fill shorten dedent indent TextWrapper", "", "", ""),
	"time":                  sroPyExports("time time_ns monotonic monotonic_ns perf_counter perf_counter_ns gmtime localtime mktime strftime strptime asctime ctime sleep", "", "", ""),
	"tomllib":               sroPyExports("load loads TOMLDecodeError", "", "", ""),
	"types":                 sroPyExports("SimpleNamespace", "", "", ""),
	"typing":                sroPyExports("TypeVar cast", "", "Any Union Optional List Dict Set Tuple Sequence Mapping Iterable Iterator Callable Literal Final ClassVar NamedTuple TypedDict", ""),
	"unicodedata":           sroPyExports("normalize name lookup category", "", "", ""),
	"urllib":                sroPyExports("", "", "", "parse"),
	"urllib.parse":          sroPyExports("urlparse urlsplit urlunparse urlunsplit urljoin urldefrag parse_qs parse_qsl quote quote_plus unquote unquote_plus urlencode", "", "", ""),
	"uuid":                  sroPyExports("uuid3 uuid4 uuid5", "UUID", "NAMESPACE_DNS NAMESPACE_URL NAMESPACE_OID NAMESPACE_X500", ""),
	"warnings":              sroPyExports("warn filterwarnings simplefilter catch_warnings", "", "", ""),
	"xml":                   sroPyExports("", "", "", "etree"),
	"xml.etree":             sroPyExports("", "", "", "ElementTree"),
	"xml.etree.ElementTree": sroPyExports("parse fromstring tostring ElementTree Element", "", "", ""),
	"zipfile":               sroPyExports("ZipFile PyZipFile Path is_zipfile BadZipFile", "", "ZIP_STORED ZIP_DEFLATED", ""),
	"zlib":                  sroPyExports("compress decompress crc32 adler32", "", "", ""),
}

func strictReadonlyNodeExecFlags(language string, strictReadonly, viaLocalCtxRun, nodePermSupported bool) ([]string, bool) {
	if strictReadonly && viaLocalCtxRun && nodePermSupported && language == "javascript" {
		return []string{"--permission", "--allow-fs-read=*"}, true
	}
	return nil, false
}

func strictReadonlyCodeAllowlistHit(language, code string) string {
	return strictReadonlyCodeAllowlistHitWithNodePerm(language, code, false)
}

func strictReadonlyCodeAllowlistHitWithNodePerm(language, code string, jsNodePerm bool) string {
	switch language {
	case "python":
		return sroPyAllowlistHit(code)
	case "javascript", "typescript":
		if language == "typescript" {
			jsNodePerm = false
		}
		return sroJSAllowlistHit(code, jsNodePerm)
	case "perl", "ruby", "php", "r", "elixir":
		if strictReadonlyBlockLegacyScripting {
			return "allowlist: [lang-legacy] scripting language " + language + " not allowed in strict readonly"
		}
		return ""
	default:
		return ""
	}
}

type sroPyTokKind uint8

const (
	sroPyId sroPyTokKind = iota
	sroPyNum
	sroPyStr
	sroPyTokOp
	sroPyNL
)

type sroPyTok struct {
	kind      sroPyTokKind
	val       string
	isDynamic bool
	indentCol int
}

func (t sroPyTok) isOp(op string) bool {
	return t.kind == sroPyTokOp && t.val == op
}

func (t sroPyTok) isId(v string) bool {
	return t.kind == sroPyId && t.val == v
}

func sroNormNL(code string) string {
	code = strings.TrimPrefix(code, "\xef\xbb\xbf")
	if strings.IndexByte(code, '\r') < 0 {
		return code
	}
	var b strings.Builder
	b.Grow(len(code))
	for i := 0; i < len(code); i++ {
		if code[i] == '\r' {
			b.WriteByte('\n')
			if i+1 < len(code) && code[i+1] == '\n' {
				i++
			}
		} else {
			b.WriteByte(code[i])
		}
	}
	return b.String()
}

func sroPyBadCoding(norm string) bool {
	rest := norm
	for lineNum := 1; lineNum <= 2 && len(rest) > 0; lineNum++ {
		nl := strings.IndexByte(rest, '\n')
		var line string
		if nl >= 0 {
			line = rest[:nl]
			rest = rest[nl+1:]
		} else {
			line = rest
			rest = ""
		}
		j := 0
		for j < len(line) && (line[j] == ' ' || line[j] == '\t' || line[j] == '\f') {
			j++
		}
		if j >= len(line) {
			continue
		}
		if line[j] != '#' {
			break
		}
		comment := strings.ToLower(line[j+1:])
		if enc := sroExtractCodingName(comment); enc != "" {
			clean := strings.ReplaceAll(strings.ReplaceAll(enc, "_", "-"), ".", "-")
			if clean != "utf-8" && clean != "utf8" && clean != "ascii" && clean != "us-ascii" {
				return true
			}
			return false
		}
	}
	return false
}

func sroExtractCodingName(lowerComment string) string {
	idx := strings.Index(lowerComment, "coding")
	for idx >= 0 {
		after := idx + len("coding")
		if after < len(lowerComment) && (lowerComment[after] == ':' || lowerComment[after] == '=') {
			k := after + 1
			for k < len(lowerComment) && (lowerComment[k] == ' ' || lowerComment[k] == '\t') {
				k++
			}
			start := k
			for k < len(lowerComment) {
				c := lowerComment[k]
				if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
					k++
				} else {
					break
				}
			}
			if k > start {
				return lowerComment[start:k]
			}
		}
		next := strings.Index(lowerComment[after:], "coding")
		if next < 0 {
			break
		}
		idx = after + next
	}
	return ""
}

func sroIsASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func sroIsASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func sroIsPyIdentStart(b byte) bool {
	return sroIsASCIIAlpha(b) || b == '_'
}

func sroIsPyIdentCont(b byte) bool {
	return sroIsASCIIAlpha(b) || sroIsASCIIDigit(b) || b == '_'
}

func sroPyValidPrefix(p string) (isRaw, isBytes, isF, ok bool) {
	switch strings.ToLower(p) {
	case "":
		return false, false, false, true
	case "r":
		return true, false, false, true
	case "u":
		return false, false, false, true
	case "b":
		return false, true, false, true
	case "f":
		return false, false, true, true
	case "rb", "br":
		return true, true, false, true
	case "rf", "fr":
		return true, false, true, true
	default:
		return false, false, false, false
	}
}

func sroPyDecodeSimpleStr(raw string, isRaw bool) (string, bool) {
	if isRaw {
		return raw, true
	}
	if strings.IndexByte(raw, '\\') < 0 {
		return raw, true
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			b.WriteByte(raw[i])
			continue
		}
		if i+1 >= len(raw) {
			return "", false
		}
		i++
		switch raw[i] {
		case '\\', '\'', '"':
			b.WriteByte(raw[i])
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\n':
		default:
			return "", false
		}
	}
	return b.String(), true
}

func sroPyMatchingOpen(closeCh byte) byte {
	switch closeCh {
	case ')':
		return '('
	case ']':
		return '['
	case '}':
		return '{'
	default:
		return 0
	}
}

func sroPyLex(norm string) ([]sroPyTok, string) {
	var toks []sroPyTok
	var deferredExprs [][]sroPyTok
	n := len(norm)
	i := 0
	delimStack := make([]byte, 0, 16)
	delimBad := false
	atLineStart := true
	curIndent := 0

	emitTok := func(t sroPyTok) {
		if atLineStart && t.kind != sroPyNL {
			t.indentCol = curIndent
			atLineStart = false
		}
		if t.kind == sroPyStr && len(toks) > 0 && toks[len(toks)-1].kind == sroPyStr {
			toks[len(toks)-1].isDynamic = true
			t.isDynamic = true
		}
		toks = append(toks, t)
	}

	for i < n {
		b := norm[i]
		if b == ' ' || b == '\t' {
			if atLineStart && len(delimStack) == 0 {
				if b == '\t' {
					curIndent = (curIndent/8 + 1) * 8
				} else {
					curIndent++
				}
			}
			i++
			continue
		}
		if b == '\n' {
			i++
			if len(delimStack) == 0 {
				if len(toks) > 0 && toks[len(toks)-1].kind != sroPyNL {
					toks = append(toks, sroPyTok{kind: sroPyNL, val: "\n"})
				}
				atLineStart = true
				curIndent = 0
			}
			continue
		}
		if b < 0x20 || b == 0x7f {
			return nil, "allowlist: [py-ctrl-char] blocked"
		}
		if b >= 0x80 {
			return nil, "allowlist: [py-non-ascii] blocked"
		}
		if b == '#' {
			for i < n && norm[i] != '\n' {
				i++
			}
			continue
		}
		if b == '\\' {
			if i+1 < n && norm[i+1] == '\n' {
				i += 2
				continue
			}
			return nil, "allowlist: [py-stray-backslash] blocked"
		}

		if b == '\'' || b == '"' || (sroIsASCIIAlpha(b) && i+1 < n) {
			pEnd := i
			if b != '\'' && b != '"' {
				for pEnd < n && pEnd-i < 2 && sroIsASCIIAlpha(norm[pEnd]) {
					pEnd++
				}
			}
			if pEnd < n && (norm[pEnd] == '\'' || norm[pEnd] == '"') {
				isRaw, isBytes, isF, okPref := sroPyValidPrefix(norm[i:pEnd])
				if okPref {
					tok, extraExprs, nextPos, unclosed, badFStr, innerHit := sroPyScanString(norm, pEnd, isRaw, isBytes, isF)
					if innerHit != "" {
						return nil, innerHit
					}
					if unclosed {
						return nil, "allowlist: [py-unclosed-string] blocked"
					}
					if badFStr {
						return nil, "allowlist: [py-fstring-syntax] blocked"
					}
					emitTok(tok)
					if len(extraExprs) > 0 {
						deferredExprs = append(deferredExprs, extraExprs...)
					}
					i = nextPos
					continue
				}
			}
		}

		if sroIsPyIdentStart(b) {
			start := i
			i++
			for i < n && sroIsPyIdentCont(norm[i]) {
				i++
			}
			emitTok(sroPyTok{kind: sroPyId, val: norm[start:i]})
			continue
		}

		if sroIsASCIIDigit(b) || (b == '.' && i+1 < n && sroIsASCIIDigit(norm[i+1])) {
			start := i
			if b == '.' {
				i += 2
			} else {
				i++
			}
			for i < n {
				c := norm[i]
				if sroIsASCIIDigit(c) || sroIsASCIIAlpha(c) || c == '_' || c == '.' {
					if (c == 'e' || c == 'E') && i+1 < n && (norm[i+1] == '+' || norm[i+1] == '-') {
						i += 2
						continue
					}
					i++
				} else {
					break
				}
			}
			emitTok(sroPyTok{kind: sroPyNum, val: norm[start:i]})
			continue
		}

		if b == '(' || b == '[' || b == '{' {
			delimStack = append(delimStack, b)
			emitTok(sroPyTok{kind: sroPyTokOp, val: string(b)})
			i++
			continue
		}
		if b == ')' || b == ']' || b == '}' {
			if len(delimStack) == 0 || delimStack[len(delimStack)-1] != sroPyMatchingOpen(b) {
				delimBad = true
				break
			}
			delimStack = delimStack[:len(delimStack)-1]
			emitTok(sroPyTok{kind: sroPyTokOp, val: string(b)})
			i++
			continue
		}

		op, step := sroPyScanOp(norm, i)
		if step == 0 {
			return nil, "allowlist: [py-unknown-char] blocked"
		}
		emitTok(sroPyTok{kind: sroPyTokOp, val: op})
		i += step
	}

	if delimBad || len(delimStack) > 0 {
		return nil, "allowlist: [py-delim-mismatch] blocked"
	}
	if len(toks) > 0 && toks[len(toks)-1].kind == sroPyNL {
		toks = toks[:len(toks)-1]
	}
	for _, exprToks := range deferredExprs {
		if len(toks) > 0 && toks[len(toks)-1].kind != sroPyNL {
			toks = append(toks, sroPyTok{kind: sroPyNL, val: "\n"})
		}
		toks = append(toks, sroPyTok{kind: sroPyTokOp, val: "(", indentCol: 0})
		for _, et := range exprToks {
			if et.kind != sroPyNL {
				et.indentCol = 0
				toks = append(toks, et)
			}
		}
		toks = append(toks, sroPyTok{kind: sroPyTokOp, val: ")"})
	}
	return toks, ""
}

var (
	sroPyOps3 = sroWordSet("... **= //= <<= >>=")
	sroPyOps2 = sroWordSet("** // << >> <= >= == != := -> += -= *= /= %= @= &= |= ^=")
)

func sroPyScanOp(s string, i int) (string, int) {
	if i+3 <= len(s) && sroPyOps3[s[i:i+3]] {
		return s[i : i+3], 3
	}
	if i+2 <= len(s) && sroPyOps2[s[i:i+2]] {
		return s[i : i+2], 2
	}
	if strings.IndexByte("+-*/%@&|^~<>=.,:;", s[i]) >= 0 {
		return s[i : i+1], 1
	}
	return "", 0
}

func sroPyScanString(s string, qPos int, isRaw, isBytes, isF bool) (sroPyTok, [][]sroPyTok, int, bool, bool, string) {
	q := s[qPos]
	triple := qPos+2 < len(s) && s[qPos+1] == q && s[qPos+2] == q
	qLen := 1
	if triple {
		qLen = 3
	}
	i := qPos + qLen
	n := len(s)
	if !isF {
		contentStart := i
		for i < n {
			c := s[i]
			if c == '\\' {
				if i+1 >= n {
					return sroPyTok{}, nil, 0, true, false, ""
				}
				i += 2
				continue
			}
			if !triple && c == '\n' {
				return sroPyTok{}, nil, 0, true, false, ""
			}
			if c == q && (!triple || (i+2 < n && s[i+1] == q && s[i+2] == q)) {
				raw := s[contentStart:i]
				if isBytes {
					return sroPyTok{kind: sroPyStr, val: raw, isDynamic: true}, nil, i + qLen, false, false, ""
				}
				decoded, ok := sroPyDecodeSimpleStr(raw, isRaw)
				return sroPyTok{kind: sroPyStr, val: decoded, isDynamic: !ok}, nil, i + qLen, false, false, ""
			}
			i++
		}
		return sroPyTok{}, nil, 0, true, false, ""
	}

	var extra [][]sroPyTok
	for i < n {
		c := s[i]
		if !triple && c == '\n' {
			return sroPyTok{}, nil, 0, true, false, ""
		}
		if c == q && (!triple || (i+2 < n && s[i+1] == q && s[i+2] == q)) {
			return sroPyTok{kind: sroPyStr, val: "", isDynamic: true}, extra, i + qLen, false, false, ""
		}
		if c == '\\' {
			if i+1 >= n {
				return sroPyTok{}, nil, 0, true, false, ""
			}
			if !isRaw && s[i+1] == 'N' && i+2 < n && s[i+2] == '{' {
				k := i + 3
				for k < n && s[k] != '}' && s[k] != '\n' {
					ch := s[k]
					if !sroIsASCIIAlpha(ch) && !sroIsASCIIDigit(ch) && ch != ' ' && ch != '-' {
						return sroPyTok{}, nil, 0, false, true, ""
					}
					k++
				}
				if k >= n || s[k] != '}' || k == i+3 {
					return sroPyTok{}, nil, 0, false, true, ""
				}
				i = k + 1
				continue
			}
			if s[i+1] == '\\' || s[i+1] == q || s[i+1] == '\n' {
				i += 2
				continue
			}
			i++
			continue
		}
		if c == '}' {
			if i+1 < n && s[i+1] == '}' {
				i += 2
				continue
			}
			return sroPyTok{}, nil, 0, false, true, ""
		}
		if c == '{' {
			if i+1 < n && s[i+1] == '{' {
				i += 2
				continue
			}
			exprs, afterClose, okF, innerHit := sroPyScanFStringField(s, i+1)
			if innerHit != "" {
				return sroPyTok{}, nil, 0, false, false, innerHit
			}
			if !okF {
				return sroPyTok{}, nil, 0, false, true, ""
			}
			extra = append(extra, exprs...)
			i = afterClose
			continue
		}
		i++
	}
	return sroPyTok{}, nil, 0, true, false, ""
}

func sroPyScanFStringField(s string, start int) ([][]sroPyTok, int, bool, string) {
	n := len(s)
	i := start
	depth := 0
	exprEnd := -1
	specStart := -1

	for i < n {
		b := s[i]
		if b == '#' {
			for i < n && s[i] != '\n' {
				i++
			}
			continue
		}
		if b == '\'' || b == '"' || (sroIsASCIIAlpha(b) && i+1 < n) {
			pEnd := i
			if b != '\'' && b != '"' {
				for pEnd < n && pEnd-i < 2 && sroIsASCIIAlpha(s[pEnd]) {
					pEnd++
				}
			}
			if pEnd < n && (s[pEnd] == '\'' || s[pEnd] == '"') {
				isRaw, isBytes, isF, okPref := sroPyValidPrefix(s[i:pEnd])
				if okPref {
					_, _, nextPos, unclosed, badF, innerHit := sroPyScanString(s, pEnd, isRaw, isBytes, isF)
					if innerHit != "" {
						return nil, 0, false, innerHit
					}
					if unclosed || badF {
						return nil, 0, false, ""
					}
					i = nextPos
					continue
				}
			}
		}
		if b == '(' || b == '[' || b == '{' {
			depth++
			i++
			continue
		}
		if b == ')' || b == ']' {
			if depth == 0 {
				return nil, 0, false, ""
			}
			depth--
			i++
			continue
		}
		if b == '}' {
			if depth == 0 {
				if exprEnd < 0 {
					exprEnd = i
				}
				break
			}
			depth--
			i++
			continue
		}
		if depth == 0 {
			if b == '!' && i+2 < n && (s[i+1] == 'r' || s[i+1] == 's' || s[i+1] == 'a') && (s[i+2] == ':' || s[i+2] == '}') {
				if exprEnd < 0 {
					exprEnd = i
				}
				i += 2
				continue
			}
			if b == ':' && (i+1 >= n || s[i+1] != '=') {
				if exprEnd < 0 {
					exprEnd = i
				}
				specStart = i + 1
				i++
				break
			}
		}
		i++
	}
	if exprEnd < 0 {
		return nil, 0, false, ""
	}
	rawExpr := strings.TrimSpace(s[start:exprEnd])
	if strings.HasSuffix(rawExpr, "=") && !strings.HasSuffix(rawExpr, "==") &&
		!strings.HasSuffix(rawExpr, "!=") && !strings.HasSuffix(rawExpr, "<=") &&
		!strings.HasSuffix(rawExpr, ">=") && !strings.HasSuffix(rawExpr, ":=") {
		rawExpr = strings.TrimSpace(rawExpr[:len(rawExpr)-1])
	}
	if rawExpr == "" {
		return nil, 0, false, ""
	}
	mainToks, innerHit := sroPyLex(rawExpr)
	if innerHit != "" {
		return nil, 0, false, innerHit
	}
	if len(mainToks) == 0 {
		return nil, 0, false, ""
	}
	out := [][]sroPyTok{mainToks}
	if specStart < 0 {
		if i >= n || s[i] != '}' {
			return nil, 0, false, ""
		}
		return out, i + 1, true, ""
	}
	k := specStart
	for k < n {
		if s[k] == '}' {
			return out, k + 1, true, ""
		}
		if s[k] == '{' {
			subExprs, nextK, subOK, subHit := sroPyScanFStringField(s, k+1)
			if subHit != "" {
				return nil, 0, false, subHit
			}
			if !subOK {
				return nil, 0, false, ""
			}
			out = append(out, subExprs...)
			k = nextK
			continue
		}
		k++
	}
	return nil, 0, false, ""
}

var sroPyBadIdents = sroWordSet("eval exec compile __import__ breakpoint input setattr delattr globals locals dir help quit copyright credits license global nonlocal")

var sroPyProtBuiltins = sroWordSet("open type isinstance issubclass getattr vars print eval exec compile __import__ setattr delattr globals locals dir breakpoint input")

var sroPyDunderDefs = sroWordSet("__init__ __post_init__ __repr__ __str__ __len__ __iter__ __next__ __contains__ __bool__ __hash__")

var sroPyBaseBuiltins = sroWordSet("object BaseException Exception ValueError TypeError RuntimeError KeyError IndexError OSError AttributeError LookupError")

var sroPyTypeCmpBuiltins = sroWordSet("int str float bool bytes bytearray list dict set frozenset tuple complex")

var sroPyReplaceKw = sroWordSet("year month day hour minute second microsecond tzinfo fold name mtime mode uid gid uname gname")

var sroPyBasicCfgKw = sroWordSet("level format datefmt style force stream")

var sroPyBadSQLKw = sroWordSet("VACUUM ATTACH DETACH INSERT UPDATE DELETE REPLACE CREATE DROP ALTER REINDEX ANALYZE BEGIN COMMIT END ROLLBACK SAVEPOINT RELEASE")

func sroPyIsStmtAssignOp(t sroPyTok) bool {
	if t.kind != sroPyTokOp {
		return false
	}
	switch t.val {
	case "=", "+=", "-=", "*=", "/=", "//=", "%=", "**=", "@=", "&=", "|=", "^=", "<<=", ">>=":
		return true
	default:
		return false
	}
}

func sroPyIsAnyAssignOp(t sroPyTok) bool {
	return sroPyIsStmtAssignOp(t) || t.isOp(":=")
}

func sroPyIsDunderOrMangled(name string) bool {
	if strings.HasPrefix(name, "__") || strings.HasSuffix(name, "__") {
		return true
	}
	if strings.HasPrefix(name, "_") && strings.Contains(name[1:], "__") {
		return true
	}
	return false
}

func sroPyMatchDelim(toks []sroPyTok, openIdx int, openOp, closeOp string) int {
	if openIdx < 0 || openIdx >= len(toks) || !toks[openIdx].isOp(openOp) {
		return -1
	}
	depth := 0
	for i := openIdx; i < len(toks); i++ {
		if toks[i].isOp(openOp) {
			depth++
		} else if toks[i].isOp(closeOp) {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func sroPySplitTopArgs(toks []sroPyTok, openIdx, closeIdx int) [][]sroPyTok {
	if closeIdx <= openIdx+1 {
		return nil
	}
	var args [][]sroPyTok
	depth := 0
	start := openIdx + 1
	for i := openIdx + 1; i < closeIdx; i++ {
		if toks[i].isOp("(") || toks[i].isOp("[") || toks[i].isOp("{") {
			depth++
		} else if toks[i].isOp(")") || toks[i].isOp("]") || toks[i].isOp("}") {
			depth--
		} else if depth == 0 && toks[i].isOp(",") {
			args = append(args, toks[start:i])
			start = i + 1
		}
	}
	if start < closeIdx {
		args = append(args, toks[start:closeIdx])
	}
	return args
}

type sroPyCallArg struct {
	kw       string
	val      []sroPyTok
	valStart int
	isStar   bool
	isKwStar bool
}

func sroPyParseCallArgs(toks []sroPyTok, openIdx, closeIdx int) []sroPyCallArg {
	if closeIdx <= openIdx+1 {
		return nil
	}
	var out []sroPyCallArg
	depth := 0
	start := openIdx + 1
	flush := func(a, b int) {
		if a >= b {
			return
		}
		seg := toks[a:b]
		if seg[0].isOp("**") {
			out = append(out, sroPyCallArg{val: seg[1:], valStart: a + 1, isKwStar: true})
			return
		}
		if seg[0].isOp("*") {
			out = append(out, sroPyCallArg{val: seg[1:], valStart: a + 1, isStar: true})
			return
		}
		if len(seg) >= 2 && seg[0].kind == sroPyId && seg[1].isOp("=") {
			out = append(out, sroPyCallArg{kw: seg[0].val, val: seg[2:], valStart: a + 2})
			return
		}
		out = append(out, sroPyCallArg{val: seg, valStart: a})
	}
	for i := openIdx + 1; i < closeIdx; i++ {
		if toks[i].isOp("(") || toks[i].isOp("[") || toks[i].isOp("{") {
			depth++
		} else if toks[i].isOp(")") || toks[i].isOp("]") || toks[i].isOp("}") {
			depth--
		} else if depth == 0 && toks[i].isOp(",") {
			flush(start, i)
			start = i + 1
		}
	}
	if start < closeIdx {
		flush(start, closeIdx)
	}
	return out
}

func sroPyStaticStr(seg []sroPyTok) (string, bool) {
	if len(seg) == 1 && seg[0].kind == sroPyStr && !seg[0].isDynamic {
		return seg[0].val, true
	}
	return "", false
}

func sroPyStaticBool(seg []sroPyTok) (bool, bool) {
	if len(seg) == 1 && seg[0].kind == sroPyId {
		if seg[0].val == "True" {
			return true, true
		}
		if seg[0].val == "False" {
			return false, true
		}
	}
	return false, false
}

func sroPyIsStdioOrNone(seg []sroPyTok, valStart int, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	if len(seg) == 1 && seg[0].isId("None") {
		return true
	}
	if len(seg) == 3 && seg[0].kind == sroPyId && confinedMods[seg[0].val] == "sys" &&
		seg[1].isOp(".") && seg[2].kind == sroPyId &&
		(seg[2].val == "stdout" || seg[2].val == "stderr") {
		validStdioTok[valStart+2] = true
		return true
	}
	return false
}

func sroPyIsReadonlyOpenModeStr(mode string, allowTarStream bool) bool {
	if allowTarStream {
		switch mode {
		case "r", "r:*", "r:", "r:gz", "r:bz2", "r:xz":
			return true
		default:
			return false
		}
	}
	if mode == "" {
		return false
	}
	hasR := false
	for i := 0; i < len(mode); i++ {
		switch mode[i] {
		case 'r':
			hasR = true
		case 'b', 't', 'U':
		default:
			return false
		}
	}
	return hasR
}

var sroPyLegacyModuleOpens = sroWordSet("codecs builtins _io wave aifc sunau")

func sroPyLooksLikeWriteModeStr(s string) bool {
	if s == "" {
		return false
	}
	hasWrite := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'w', 'a', 'x', '+':
			hasWrite = true
		case 'r', 'b', 't', 'U':
		default:
			return false
		}
	}
	return hasWrite
}

func sroPyCheckDbmOpenArgs(args []sroPyCallArg) (string, bool) {
	posCount := 0
	hasFileKw := false
	hasFlag := false
	var flagSeg []sroPyTok
	for _, a := range args {
		if a.isStar || a.isKwStar {
			return "mode", false
		}
		if a.kw != "" {
			switch a.kw {
			case "file", "filename":
				hasFileKw = true
			case "flag":
				if hasFlag {
					return "mode", false
				}
				flagSeg = a.val
				hasFlag = true
			case "mode":
				if len(a.val) != 1 || a.val[0].kind != sroPyNum {
					return "mode", false
				}
			default:
				return "mode", false
			}
			continue
		}
		posCount++
		switch posCount {
		case 1:
		case 2:
			if hasFlag {
				return "mode", false
			}
			flagSeg = a.val
			hasFlag = true
		case 3:
			if len(a.val) != 1 || a.val[0].kind != sroPyNum {
				return "mode", false
			}
		default:
			return "mode", false
		}
	}
	if posCount == 0 && !hasFileKw {
		return "mode", false
	}
	if hasFlag {
		fStr, ok := sroPyStaticStr(flagSeg)
		if !ok || fStr != "r" {
			return "mode", false
		}
	}
	return "", true
}

func sroPyCheckOpenArgsExt(args []sroPyCallArg, isBuiltinOrFileIO, allowTarStream, isMethod, isDbm, isLegacyModOpen bool) (string, bool) {
	if isDbm {
		return sroPyCheckDbmOpenArgs(args)
	}
	posCount := 0
	var firstPosSeg, modeSeg []sroPyTok
	hasMode := false
	for _, a := range args {
		if a.isStar || a.isKwStar {
			return "mode", false
		}
		if a.kw != "" {
			switch a.kw {
			case "opener":
				return "opener", false
			case "mode":
				modeSeg = a.val
				hasMode = true
			case "file", "name", "buffering", "encoding", "errors", "newline", "closefd",
				"compresslevel", "format", "filter", "preset", "allowZip64", "metadata_encoding":
			default:
				return "mode", false
			}
			continue
		}
		posCount++
		if posCount == 1 {
			firstPosSeg = a.val
		} else if posCount == 2 {
			modeSeg = a.val
			hasMode = true
		}
		if isBuiltinOrFileIO && posCount >= 8 {
			return "opener", false
		}
		if isBuiltinOrFileIO && posCount == 4 && len(args) == 4 {
			if !(len(a.val) == 1 && a.val[0].isId("None")) {
				return "opener", false
			}
		}
	}
	if posCount == 0 && !isMethod {
		hasPathKw := false
		for _, a := range args {
			if a.kw == "file" || a.kw == "name" {
				hasPathKw = true
			}
		}
		if !hasPathKw {
			return "mode", false
		}
	}
	if isMethod && !isLegacyModOpen && posCount == 1 && !hasMode {
		s1, ok := sroPyStaticStr(firstPosSeg)
		if !ok || sroPyLooksLikeWriteModeStr(s1) {
			return "mode", false
		}
	}
	if !hasMode {
		return "", true
	}
	mStr, ok := sroPyStaticStr(modeSeg)
	if !ok || !sroPyIsReadonlyOpenModeStr(mStr, allowTarStream) {
		return "mode", false
	}
	return "", true
}

func sroPySqliteRO(args []sroPyCallArg) bool {
	var dbSeg []sroPyTok
	hasDB := false
	uriTrue := false
	posCount := 0
	for _, a := range args {
		if a.isStar || a.isKwStar {
			return false
		}
		if a.kw != "" {
			switch a.kw {
			case "database":
				dbSeg = a.val
				hasDB = true
			case "uri":
				b, ok := sroPyStaticBool(a.val)
				if !ok || !b {
					return false
				}
				uriTrue = true
			case "timeout", "detect_types", "isolation_level", "check_same_thread":
			default:
				return false
			}
			continue
		}
		posCount++
		if posCount == 1 {
			dbSeg = a.val
			hasDB = true
		} else {
			return false
		}
	}
	if !hasDB || !uriTrue {
		return false
	}
	u, ok := sroPyStaticStr(dbSeg)
	if !ok || !strings.HasPrefix(u, "file:") {
		return false
	}
	if hash := strings.IndexByte(u, '#'); hash >= 0 {
		u = u[:hash]
	}
	qIdx := strings.IndexByte(u, '?')
	if qIdx < 0 {
		return false
	}
	query := u[qIdx+1:]
	hasModeRO := false
	for _, part := range strings.Split(query, "&") {
		if part == "mode=ro" {
			hasModeRO = true
		} else if strings.HasPrefix(part, "mode=") {
			return false
		}
	}
	return hasModeRO
}

func sroPyReadonlySQL(args []sroPyCallArg) bool {
	if len(args) < 1 || len(args) > 2 {
		return false
	}
	for _, a := range args {
		if a.isStar || a.isKwStar || a.kw != "" {
			return false
		}
	}
	sqlStr, ok := sroPyStaticStr(args[0].val)
	if !ok {
		return false
	}
	if strings.Contains(sqlStr, ";") || strings.Contains(sqlStr, "--") || strings.Contains(sqlStr, "/*") {
		return false
	}
	var words []string
	i := 0
	for i < len(sqlStr) {
		c := sqlStr[i]
		if c == '\'' {
			i++
			for i < len(sqlStr) {
				if sqlStr[i] == '\'' {
					if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			continue
		}
		if c == '"' {
			i++
			for i < len(sqlStr) && sqlStr[i] != '"' {
				i++
			}
			if i < len(sqlStr) {
				i++
			}
			continue
		}
		if sroIsASCIIAlpha(c) || c == '_' {
			start := i
			i++
			for i < len(sqlStr) && (sroIsASCIIAlpha(sqlStr[i]) || sroIsASCIIDigit(sqlStr[i]) || sqlStr[i] == '_') {
				i++
			}
			words = append(words, strings.ToUpper(sqlStr[start:i]))
			continue
		}
		if c == '=' && len(words) > 0 && words[0] == "PRAGMA" {
			return false
		}
		i++
	}
	if len(words) == 0 {
		return false
	}
	switch words[0] {
	case "SELECT", "WITH", "EXPLAIN", "PRAGMA":
	default:
		return false
	}
	for _, w := range words {
		if sroPyBadSQLKw[w] {
			return false
		}
	}
	return true
}

func sroPyClassInfoOK(toks []sroPyTok, start, end int, mark map[int]bool) bool {
	if start >= end {
		return false
	}
	depth := 0
	for i := start; i < end; i++ {
		if toks[i].isOp("(") {
			depth++
		} else if toks[i].isOp(")") {
			depth--
		} else if depth == 0 && toks[i].isOp("|") {
			return sroPyClassInfoOK(toks, start, i, mark) &&
				sroPyClassInfoOK(toks, i+1, end, mark)
		}
	}
	if toks[start].isOp("(") && sroPyMatchDelim(toks, start, "(", ")") == end-1 {
		elems := sroPySplitTopArgs(toks, start, end-1)
		if len(elems) == 0 {
			return true
		}
		d := 0
		segStart := start + 1
		for i := start + 1; i < end-1; i++ {
			if toks[i].isOp("(") || toks[i].isOp("[") || toks[i].isOp("{") {
				d++
			} else if toks[i].isOp(")") || toks[i].isOp("]") || toks[i].isOp("}") {
				d--
			} else if d == 0 && toks[i].isOp(",") {
				if i > segStart && !sroPyClassInfoOK(toks, segStart, i, mark) {
					return false
				}
				segStart = i + 1
			}
		}
		if segStart < end-1 {
			return sroPyClassInfoOK(toks, segStart, end-1, mark)
		}
		return true
	}
	for i := start; i < end; i++ {
		if (i-start)%2 == 0 {
			if toks[i].kind != sroPyId {
				return false
			}
		} else {
			if !toks[i].isOp(".") {
				return false
			}
		}
	}
	if (end-start)%2 != 1 {
		return false
	}
	mark[end-1] = true
	return true
}

func sroPyExtractNamedtupleFields(args []sroPyCallArg, out map[string]bool) {
	if len(args) < 2 {
		return
	}
	seg := args[1].val
	if s, ok := sroPyStaticStr(seg); ok {
		cleaned := strings.ReplaceAll(s, ",", " ")
		for _, f := range strings.Fields(cleaned) {
			if len(f) > 0 && sroIsPyIdentStart(f[0]) && !strings.HasPrefix(f, "_") && !sroPyNonROMembers[f] {
				out[f] = true
			}
		}
		return
	}
	if len(seg) >= 2 && (seg[0].isOp("[") || seg[0].isOp("(")) {
		for _, t := range seg[1 : len(seg)-1] {
			if t.kind == sroPyStr && !t.isDynamic && len(t.val) > 0 &&
				sroIsPyIdentStart(t.val[0]) && !strings.HasPrefix(t.val, "_") && !sroPyNonROMembers[t.val] {
				out[t.val] = true
			}
		}
	}
}

func sroPyExtractAddArgDest(args []sroPyCallArg, out map[string]bool) {
	var longOpt, shortOpt string
	for _, a := range args {
		if a.kw == "dest" {
			if s, ok := sroPyStaticStr(a.val); ok && len(s) > 0 && !strings.HasPrefix(s, "_") && !sroPyNonROMembers[s] {
				out[s] = true
			}
			return
		}
		if a.kw == "" {
			if s, ok := sroPyStaticStr(a.val); ok {
				if strings.HasPrefix(s, "--") && len(s) > 2 {
					longOpt = strings.ReplaceAll(strings.TrimLeft(s, "-"), "-", "_")
				} else if strings.HasPrefix(s, "-") && len(s) > 1 && longOpt == "" {
					shortOpt = strings.ReplaceAll(strings.TrimLeft(s, "-"), "-", "_")
				}
			}
		}
	}
	cand := longOpt
	if cand == "" {
		cand = shortOpt
	}
	if cand != "" && !strings.HasPrefix(cand, "_") && !sroPyNonROMembers[cand] {
		out[cand] = true
	}
}

func sroPyOpenHit(args []sroPyCallArg, isBuiltinOrFileIO, allowTarStream, isArchive bool) string {
	return sroPyOpenHitExt(args, isBuiltinOrFileIO, allowTarStream, isArchive, false, false, false)
}

func sroPyOpenHitExt(args []sroPyCallArg, isBuiltinOrFileIO, allowTarStream, isArchive, isMethod, isDbm, isLegacyModOpen bool) string {
	kind, ok := sroPyCheckOpenArgsExt(args, isBuiltinOrFileIO, allowTarStream, isMethod, isDbm, isLegacyModOpen)
	if ok {
		return ""
	}
	if kind == "opener" {
		return "allowlist: [py-open-opener] blocked"
	}
	if isArchive {
		return "allowlist: [py-archive-mode] blocked"
	}
	return "allowlist: [py-open-mode] blocked"
}

func sroPyValidStreamHandlerArgs(args []sroPyCallArg, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	if len(args) == 0 {
		return true
	}
	if len(args) > 1 {
		return false
	}
	a := args[0]
	return !a.isStar && !a.isKwStar && (a.kw == "" || a.kw == "stream") &&
		sroPyIsStdioOrNone(a.val, a.valStart, confinedMods, validStdioTok)
}

func sroPyValidBasicConfigArgs(args []sroPyCallArg, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	for _, a := range args {
		if a.isStar || a.isKwStar || a.kw == "" || !sroPyBasicCfgKw[a.kw] {
			return false
		}
		if a.kw == "stream" && !sroPyIsStdioOrNone(a.val, a.valStart, confinedMods, validStdioTok) {
			return false
		}
	}
	return true
}

func sroPyValidPprintArgs(canon string, args []sroPyCallArg, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	for idx, a := range args {
		if a.isKwStar || a.isStar {
			return false
		}
		if a.kw == "stream" || (canon == "pprint.PrettyPrinter" && a.kw == "" && idx == 3) {
			if !sroPyIsStdioOrNone(a.val, a.valStart, confinedMods, validStdioTok) {
				return false
			}
		}
	}
	return true
}

func sroPyValidJsonDumpArgs(args []sroPyCallArg, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	posCount := 0
	var fpArg *sroPyCallArg
	for idx := range args {
		a := &args[idx]
		if a.isStar || a.isKwStar {
			return false
		}
		if a.kw == "fp" {
			fpArg = a
		} else if a.kw == "" {
			posCount++
			if posCount == 2 {
				fpArg = a
			}
		}
	}
	return fpArg != nil &&
		sroPyIsStdioOrNone(fpArg.val, fpArg.valStart, confinedMods, validStdioTok) &&
		!(len(fpArg.val) == 1 && fpArg.val[0].val == "None")
}

func sroPyCheckSpecialCallable(
	canon string,
	args []sroPyCallArg,
	confinedMods map[string]string,
	validStdioTok map[int]bool,
	userAttrs map[string]bool,
) string {
	switch canon {
	case "io.open", "gzip.open", "bz2.open", "lzma.open":
		return sroPyOpenHit(args, canon == "io.open", false, false)
	case "tarfile.open", "zipfile.ZipFile", "zipfile.PyZipFile", "tarfile.TarFile",
		"io.FileIO", "gzip.GzipFile", "bz2.BZ2File", "lzma.LZMAFile":
		return sroPyOpenHit(args, canon == "io.FileIO", canon == "tarfile.open" || canon == "tarfile.TarFile", true)
	case "sqlite3.connect":
		if !sroPySqliteRO(args) {
			return "allowlist: [py-sqlite-ro] blocked"
		}
	case "logging.StreamHandler":
		if !sroPyValidStreamHandlerArgs(args, confinedMods, validStdioTok) {
			return "allowlist: [py-streamhandler-arg] blocked"
		}
	case "logging.basicConfig":
		if !sroPyValidBasicConfigArgs(args, confinedMods, validStdioTok) {
			return "allowlist: [py-basicconfig-arg] blocked"
		}
	case "pprint.pprint", "pprint.pp", "pprint.PrettyPrinter":
		if !sroPyValidPprintArgs(canon, args, confinedMods, validStdioTok) {
			return "allowlist: [py-pprint-stream] blocked"
		}
	case "json.dump":
		if !sroPyValidJsonDumpArgs(args, confinedMods, validStdioTok) {
			return "allowlist: [py-jsondump-fp] blocked"
		}
	case "collections.namedtuple":
		sroPyExtractNamedtupleFields(args, userAttrs)
	case "argparse.Namespace", "types.SimpleNamespace":
		for _, a := range args {
			if !a.isStar && !a.isKwStar && a.kw != "" && !strings.HasPrefix(a.kw, "_") && !sroPyNonROMembers[a.kw] {
				userAttrs[a.kw] = true
			}
		}
	}
	return ""
}

func sroPyParseImport(
	toks []sroPyTok,
	i, end int,
	confinedMods, confCalls, confValCls map[string]string,
	environVars, enumBaseVars, importedNames map[string]bool,
) (string, string) {
	if toks[i].val == "import" {
		k := i + 1
		if k >= end {
			return "syntax", ""
		}
		for k < end {
			if toks[k].kind != sroPyId {
				return "syntax", ""
			}
			modParts := []string{toks[k].val}
			k++
			for k < end && toks[k].isOp(".") {
				if k+1 >= end || toks[k+1].kind != sroPyId {
					return "syntax", ""
				}
				modParts = append(modParts, toks[k+1].val)
				k += 2
			}
			fullMod := strings.Join(modParts, ".")
			if _, ok := sroPyModExports[fullMod]; !ok {
				return "imp-mod", fullMod
			}
			localAlias := modParts[0]
			hasAs := false
			if k < end && toks[k].isId("as") {
				if k+1 >= end || toks[k+1].kind != sroPyId {
					return "syntax", ""
				}
				localAlias = toks[k+1].val
				hasAs = true
				k += 2
			}
			importedNames[localAlias] = true
			if hasAs {
				confinedMods[localAlias] = fullMod
			} else {
				confinedMods[modParts[0]] = modParts[0]
			}
			if k < end {
				if !toks[k].isOp(",") {
					return "syntax", ""
				}
				k++
			}
		}
		return "", ""
	}

	k := i + 1
	if k < end && (toks[k].isOp(".") || toks[k].isOp("...")) {
		return "rel", ""
	}
	if k >= end || toks[k].kind != sroPyId {
		return "syntax", ""
	}
	modParts := []string{toks[k].val}
	k++
	for k < end && toks[k].isOp(".") {
		if k+1 >= end || toks[k+1].kind != sroPyId {
			return "syntax", ""
		}
		modParts = append(modParts, toks[k+1].val)
		k += 2
	}
	if k >= end || toks[k].kind != sroPyId || toks[k].val != "import" {
		return "syntax", ""
	}
	fullMod := strings.Join(modParts, ".")
	exports, ok := sroPyModExports[fullMod]
	if !ok {
		return "from-mod", fullMod
	}
	k++
	if k < end && toks[k].isOp("*") {
		return "wild", ""
	}
	inParen := false
	if k < end && toks[k].isOp("(") {
		inParen = true
		k++
	}
	parsedAny := false
	for k < end {
		if inParen && toks[k].isOp(")") {
			k++
			inParen = false
			break
		}
		if toks[k].kind != sroPyId {
			return "syntax", ""
		}
		orig := toks[k].val
		expKind, okExp := exports[orig]
		if !okExp {
			return "from-mem", fullMod + "." + orig
		}
		local := orig
		k++
		if k < end && toks[k].isId("as") {
			if k+1 >= end || toks[k+1].kind != sroPyId {
				return "syntax", ""
			}
			local = toks[k+1].val
			k += 2
		}
		importedNames[local] = true
		parsedAny = true
		canon := fullMod + "." + orig
		switch expKind {
		case sroPyExpSubmod:
			confinedMods[local] = canon
		case sroPyExpCall:
			confCalls[local] = canon
			if fullMod == "enum" && (orig == "Enum" || orig == "IntEnum" || orig == "StrEnum" || orig == "Flag" || orig == "IntFlag") {
				enumBaseVars[local] = true
			}
		case sroPyExpValueCls:
			confValCls[local] = canon
		case sroPyExpConst:
			if canon == "os.environ" {
				environVars[local] = true
			}
		}
		if k < end && toks[k].isOp(",") {
			k++
		}
	}
	if inParen || !parsedAny || k != end {
		return "syntax", ""
	}
	return "", ""
}

func sroPyValidClassHeader(
	toks []sroPyTok,
	start, end int,
	confinedMods map[string]string,
	clsBaseTok map[int]bool,
	enumBaseNames map[string]bool,
) bool {
	if start+2 >= end || toks[start+1].kind != sroPyId {
		return false
	}
	k := start + 2
	if !toks[k].isOp("(") {
		return toks[k].isOp(":")
	}
	cp := sroPyMatchDelim(toks, k, "(", ")")
	if cp < 0 || cp+1 >= end || !toks[cp+1].isOp(":") {
		return false
	}
	for _, ba := range sroPyParseCallArgs(toks, k, cp) {
		if ba.isStar || ba.isKwStar || ba.kw != "" {
			return false
		}
		if len(ba.val) == 1 && ba.val[0].kind == sroPyId {
			bn := ba.val[0].val
			if sroPyBaseBuiltins[bn] || enumBaseNames[bn] {
				clsBaseTok[ba.valStart] = true
				continue
			}
		}
		if len(ba.val) == 3 && ba.val[0].kind == sroPyId && confinedMods[ba.val[0].val] == "enum" &&
			ba.val[1].isOp(".") && ba.val[2].kind == sroPyId &&
			(ba.val[2].val == "Enum" || ba.val[2].val == "IntEnum" || ba.val[2].val == "StrEnum" || ba.val[2].val == "Flag" || ba.val[2].val == "IntFlag") {
			clsBaseTok[ba.valStart+2] = true
			continue
		}
		return false
	}
	return true
}

func sroPyValidIsInstanceCall(toks []sroPyTok, idx int, isInstTok map[int]bool) bool {
	if idx+1 >= len(toks) || !toks[idx+1].isOp("(") {
		return false
	}
	cp := sroPyMatchDelim(toks, idx+1, "(", ")")
	if cp < 0 {
		return false
	}
	cArgs := sroPyParseCallArgs(toks, idx+1, cp)
	if len(cArgs) != 2 || cArgs[0].isStar || cArgs[0].isKwStar || cArgs[0].kw != "" ||
		cArgs[1].isStar || cArgs[1].isKwStar || cArgs[1].kw != "" {
		return false
	}
	for _, tk := range cArgs[1].val {
		if tk.isOp(":=") {
			return false
		}
	}
	return sroPyClassInfoOK(toks, cArgs[1].valStart, cArgs[1].valStart+len(cArgs[1].val), isInstTok)
}

func sroPyValidGetattrArgs(toks []sroPyTok, idx int) ([]sroPyCallArg, string, bool) {
	if idx+1 >= len(toks) || !toks[idx+1].isOp("(") {
		return nil, "", false
	}
	cp := sroPyMatchDelim(toks, idx+1, "(", ")")
	if cp < 0 {
		return nil, "", false
	}
	cArgs := sroPyParseCallArgs(toks, idx+1, cp)
	if len(cArgs) < 2 || len(cArgs) > 3 {
		return nil, "", false
	}
	for _, ca := range cArgs {
		if ca.isStar || ca.isKwStar || ca.kw != "" {
			return nil, "", false
		}
	}
	attrStr, okAttr := sroPyStaticStr(cArgs[1].val)
	if !okAttr || attrStr == "" || strings.HasPrefix(attrStr, "_") {
		return nil, "", false
	}
	return cArgs, attrStr, true
}

func sroPyValidVarsCall(toks []sroPyTok, idx int, confinedMods map[string]string, reflModTok map[int]bool) bool {
	if idx+1 >= len(toks) || !toks[idx+1].isOp("(") {
		return false
	}
	cp := sroPyMatchDelim(toks, idx+1, "(", ")")
	if cp < 0 {
		return false
	}
	cArgs := sroPyParseCallArgs(toks, idx+1, cp)
	if len(cArgs) != 1 || cArgs[0].isStar || cArgs[0].isKwStar || cArgs[0].kw != "" ||
		len(cArgs[0].val) != 1 || cArgs[0].val[0].kind != sroPyId || confinedMods[cArgs[0].val[0].val] == "" {
		return false
	}
	canonMod := confinedMods[cArgs[0].val[0].val]
	if cp+3 >= len(toks) || !toks[cp+1].isOp(".") || toks[cp+2].kind != sroPyId || toks[cp+2].val != "get" || !toks[cp+3].isOp("(") {
		return false
	}
	gcp := sroPyMatchDelim(toks, cp+3, "(", ")")
	gArgs := sroPyParseCallArgs(toks, cp+3, gcp)
	if len(gArgs) < 1 || len(gArgs) > 2 || gArgs[0].isStar || gArgs[0].isKwStar || gArgs[0].kw != "" {
		return false
	}
	keyStr, okKey := sroPyStaticStr(gArgs[0].val)
	exports := sroPyModExports[canonMod]
	kind, okExp := exports[keyStr]
	if !okKey || !okExp || kind != sroPyExpConst || keyStr == "environ" || keyStr == "stdout" || keyStr == "stderr" || keyStr == "stdin" {
		return false
	}
	reflModTok[cArgs[0].valStart] = true
	return true
}

func sroPyValidPrintArgs(args []sroPyCallArg, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	for _, a := range args {
		if a.isKwStar {
			return false
		}
		if a.kw == "file" && !sroPyIsStdioOrNone(a.val, a.valStart, confinedMods, validStdioTok) {
			return false
		}
	}
	return true
}

func sroPyValidPrintdirArgs(args []sroPyCallArg, confinedMods map[string]string, validStdioTok map[int]bool) bool {
	if len(args) == 0 {
		return true
	}
	if len(args) > 1 {
		return false
	}
	pa := args[0]
	return !pa.isStar && !pa.isKwStar && (pa.kw == "" || pa.kw == "file") &&
		sroPyIsStdioOrNone(pa.val, pa.valStart, confinedMods, validStdioTok)
}

func sroPyIsShadowBinding(toks []sroPyTok, i int, defParamToks map[int]bool) bool {
	if defParamToks[i] && (i == 0 || toks[i-1].isOp("(") || toks[i-1].isOp(",") || toks[i-1].isOp("*")) {
		return true
	}
	if i+1 < len(toks) && sroPyIsAnyAssignOp(toks[i+1]) {
		return true
	}
	if i > 0 && toks[i-1].kind == sroPyId &&
		(toks[i-1].val == "for" || toks[i-1].val == "as" || toks[i-1].val == "def" || toks[i-1].val == "class") {
		return true
	}
	return false
}

func sroPyIsValidDotAt(toks []sroPyTok, i int) bool {
	if i <= 0 || i+1 >= len(toks) || toks[i+1].kind != sroPyId {
		return false
	}
	prev := toks[i-1]
	return prev.kind == sroPyId || prev.kind == sroPyStr || prev.kind == sroPyNum ||
		prev.isOp(")") || prev.isOp("]") || prev.isOp("}")
}

func sroPyAllowlistHit(code string) string {
	norm := sroNormNL(code)
	if sroPyBadCoding(norm) {
		return "allowlist: [py-coding-cookie] blocked"
	}
	toks, lexHit := sroPyLex(norm)
	if lexHit != "" {
		return lexHit
	}
	if len(toks) == 0 {
		return ""
	}

	type lineSpan struct {
		start, end int
		indent     int
		inClass    bool
	}
	var lines []lineSpan
	for i := 0; i < len(toks); {
		if toks[i].kind == sroPyNL {
			i++
			continue
		}
		j := i
		for j < len(toks) && toks[j].kind != sroPyNL {
			j++
		}
		lines = append(lines, lineSpan{start: i, end: j, indent: toks[i].indentCol})
		i = j + 1
	}

	var classIndents []int
	inClassTok := make(map[int]bool)
	defParamToks := make(map[int]bool)
	clsBaseTok := make(map[int]bool)

	for li := 0; li < len(lines); li++ {
		ln := &lines[li]
		for len(classIndents) > 0 && ln.indent <= classIndents[len(classIndents)-1] {
			classIndents = classIndents[:len(classIndents)-1]
		}
		if len(classIndents) > 0 {
			ln.inClass = true
			for k := ln.start; k < ln.end; k++ {
				inClassTok[k] = true
			}
		}
		if toks[ln.start].isId("class") {
			classIndents = append(classIndents, ln.indent)
		}
		for k := ln.start; k < ln.end; k++ {
			if toks[k].isId("def") && k+2 < ln.end && toks[k+1].kind == sroPyId && toks[k+2].isOp("(") {
				cp := sroPyMatchDelim(toks, k+2, "(", ")")
				if cp > k+2 {
					for p := k + 3; p < cp; p++ {
						defParamToks[p] = true
					}
				}
			}
		}
	}

	confinedMods := make(map[string]string)
	confCalls := make(map[string]string)
	confValCls := make(map[string]string)
	environVars := make(map[string]bool)
	enumBaseVars := make(map[string]bool)
	importedNames := make(map[string]bool)
	importSpanToks := make(map[int]bool)

	for i := 0; i < len(toks); i++ {
		atStmtStart := i == 0 || toks[i-1].kind == sroPyNL || toks[i-1].isOp(";") || toks[i-1].isOp(":")
		if !atStmtStart || toks[i].kind != sroPyId || (toks[i].val != "import" && toks[i].val != "from") {
			continue
		}
		end := i
		depth := 0
		for end < len(toks) {
			if toks[end].isOp("(") || toks[end].isOp("[") || toks[end].isOp("{") {
				depth++
			} else if toks[end].isOp(")") || toks[end].isOp("]") || toks[end].isOp("}") {
				depth--
			} else if depth == 0 && (toks[end].kind == sroPyNL || toks[end].isOp(";")) {
				break
			}
			end++
		}
		for k := i; k < end; k++ {
			importSpanToks[k] = true
		}
		errKind, arg := sroPyParseImport(toks, i, end, confinedMods, confCalls, confValCls, environVars, enumBaseVars, importedNames)
		switch errKind {
		case "rel":
			return "allowlist: [py-relative-import] blocked"
		case "wild":
			return "allowlist: [py-wildcard-import] blocked"
		case "imp-mod":
			return "allowlist: [py-import-mod] import module " + arg + " not allowed"
		case "from-mod":
			return "allowlist: [py-from-mod] from-import module " + arg + " not allowed"
		case "from-mem":
			return "allowlist: [py-from-member] from-import member " + arg + " not allowed"
		case "syntax":
			return "allowlist: [py-import-syntax] blocked"
		}
		i = end - 1
	}

	for i := 0; i < len(toks); i++ {
		if !importSpanToks[i] && toks[i].isOp(".") && !sroPyIsValidDotAt(toks, i) {
			return "allowlist: [py-dot-syntax] blocked"
		}
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != sroPyId {
			continue
		}
		if sroPyIsDunderOrMangled(t.val) {
			if i > 0 && toks[i-1].isOp(".") {
				notCalledOrAssigned := i+1 >= len(toks) || (!toks[i+1].isOp("(") && !sroPyIsAnyAssignOp(toks[i+1]))
				if (t.val == "__name__" || t.val == "__qualname__" || t.val == "__doc__") && notCalledOrAssigned {
					continue
				}
				if t.val == "__class__" && i+2 < len(toks) && toks[i+1].isOp(".") &&
					toks[i+2].kind == sroPyId && (toks[i+2].val == "__name__" || toks[i+2].val == "__qualname__") {
					continue
				}
				return "allowlist: [py-dunder-attr] dunder or mangled attribute ." + t.val + " not allowed"
			}
			if (t.val == "__name__" || t.val == "__file__") && (i+1 >= len(toks) || !sroPyIsAnyAssignOp(toks[i+1])) {
				continue
			}
			if i > 0 && toks[i-1].isId("def") && inClassTok[i] && sroPyDunderDefs[t.val] {
				continue
			}
			return "allowlist: [py-dunder-ident] dunder or mangled identifier " + t.val + " not allowed"
		}

		if t.val == "self" && !defParamToks[i] && (i == 0 || !toks[i-1].isOp(".")) && sroPyIsShadowBinding(toks, i, defParamToks) {
			return "allowlist: [py-self-rebind] blocked"
		}

		if sroPyProtBuiltins[t.val] && (i == 0 || !toks[i-1].isOp(".")) {
			isCallKw := !defParamToks[i] && i > 0 && (toks[i-1].isOp("(") || toks[i-1].isOp(",")) && i+1 < len(toks) && toks[i+1].isOp("=")
			if !isCallKw && sroPyIsShadowBinding(toks, i, defParamToks) {
				return "allowlist: [py-builtin-shadow] shadowing builtin " + t.val + " not allowed"
			}
		}
	}

	locallyBound := make(map[string]bool)
	for i := 0; i < len(toks); i++ {
		if importSpanToks[i] || toks[i].kind != sroPyId || (i > 0 && toks[i-1].isOp(".")) {
			continue
		}
		name := toks[i].val
		isKwArg := !defParamToks[i] && i > 0 && (toks[i-1].isOp("(") || toks[i-1].isOp(",")) && i+1 < len(toks) && toks[i+1].isOp("=")
		if isKwArg {
			continue
		}
		isRebind := (i+1 < len(toks) && sroPyIsAnyAssignOp(toks[i+1])) ||
			(i > 0 && toks[i-1].kind == sroPyId && (toks[i-1].val == "def" || toks[i-1].val == "class" || toks[i-1].val == "for" || toks[i-1].val == "as"))
		if isRebind {
			if importedNames[name] && confinedMods[name] != "" {
				return "allowlist: [py-mod-rebind] reassigning imported module " + name + " not allowed"
			}
			locallyBound[name] = true
		}
	}

	for modName := range sroPyModExports {
		if strings.IndexByte(modName, '.') < 0 && !importedNames[modName] && !locallyBound[modName] {
			confinedMods[modName] = modName
		}
	}

	userAttrs := make(map[string]bool)
	selfPrivAttrs := make(map[string]bool)
	userMeths := make(map[string]bool)
	userPrivMeths := make(map[string]bool)

	for _, ln := range lines {
		first := toks[ln.start]
		if first.isId("class") {
			if !sroPyValidClassHeader(toks, ln.start, ln.end, confinedMods, clsBaseTok, enumBaseVars) {
				return "allowlist: [py-class-base] blocked"
			}
			continue
		}
		if ln.inClass {
			if first.isId("def") && ln.start+1 < ln.end && toks[ln.start+1].kind == sroPyId {
				mName := toks[ln.start+1].val
				if strings.HasPrefix(mName, "_") && !strings.HasPrefix(mName, "__") && !sroPyAllPrivMembers[mName] {
					userPrivMeths[mName] = true
				} else if !strings.HasPrefix(mName, "_") && !sroPyAllPubMembers[mName] {
					userMeths[mName] = true
				}
			} else if first.kind == sroPyId && ln.start+1 < ln.end &&
				(toks[ln.start+1].isOp("=") || toks[ln.start+1].isOp(":")) {
				fName := first.val
				if !strings.HasPrefix(fName, "_") && !sroPyNonROMembers[fName] {
					userAttrs[fName] = true
				}
			}
		}
	}

	lhsAttrValidTok := make(map[int]bool)
	for i := 0; i < len(toks); i++ {
		if importSpanToks[i] {
			continue
		}
		if toks[i].isId("del") {
			for k := i + 1; k < len(toks) && toks[k].kind != sroPyNL && !toks[k].isOp(";"); k++ {
				if toks[k].isOp(".") || (toks[k].kind == sroPyId && (environVars[toks[k].val] || confinedMods[toks[k].val] != "")) {
					return "allowlist: [py-del-attr] blocked"
				}
			}
		}
		if toks[i].isOp(".") && i > 0 && i+1 < len(toks) && toks[i+1].kind == sroPyId {
			attr := toks[i+1].val
			afterIdx := i + 2
			isAssign := false
			if afterIdx < len(toks) && sroPyIsStmtAssignOp(toks[afterIdx]) {
				isAssign = true
			} else if afterIdx < len(toks) && toks[afterIdx].isOp(":") {
				for k := afterIdx + 1; k < len(toks) && toks[k].kind != sroPyNL && !toks[k].isOp(";"); k++ {
					if toks[k].isOp("=") {
						isAssign = true
						break
					}
				}
			}
			if !isAssign {
				continue
			}
			recv := toks[i-1]
			isConfinedRecv := (recv.kind == sroPyId && (confinedMods[recv.val] != "" || confCalls[recv.val] != "" ||
				confValCls[recv.val] != "" || environVars[recv.val])) ||
				(i >= 3 && toks[i-2].isOp(".") && toks[i-3].kind == sroPyId && confinedMods[toks[i-3].val] != "")
			if isConfinedRecv {
				return "allowlist: [py-confined-attr-assign] blocked"
			}
			if strings.HasPrefix(attr, "_") {
				if recv.isId("self") && (i < 2 || !toks[i-2].isOp(".")) &&
					!strings.HasPrefix(attr, "__") && !sroPyAllPrivMembers[attr] {
					selfPrivAttrs[attr] = true
					lhsAttrValidTok[i+1] = true
					continue
				}
				return "allowlist: [py-priv-attr-assign] private attribute assignment ." + attr + " not allowed"
			}
			if sroPyNonROMembers[attr] {
				return "allowlist: [py-stdlib-attr-assign] attribute assignment to stdlib member ." + attr + " not allowed"
			}
			userAttrs[attr] = true
			lhsAttrValidTok[i+1] = true
		}
	}

	for i := 0; i < len(toks); i++ {
		if i == 0 || toks[i-1].kind == sroPyNL {
			t := toks[i]
			if t.kind == sroPyId && (t.val == "match" || t.val == "case") {
				allowedAssign := i+1 < len(toks) && sroPyIsStmtAssignOp(toks[i+1])
				allowedDot := i+2 < len(toks) && toks[i+1].isOp(".") && toks[i+2].kind == sroPyId
				if !allowedAssign && !allowedDot {
					return "allowlist: [py-match-stmt] blocked"
				}
			}
		}
	}

	isInstTok := make(map[int]bool)
	for i := 0; i < len(toks); i++ {
		if importSpanToks[i] || toks[i].kind != sroPyId || (toks[i].val != "isinstance" && toks[i].val != "issubclass") {
			continue
		}
		if i > 0 && toks[i-1].isOp(".") {
			continue
		}
		if !defParamToks[i] && i > 0 && (toks[i-1].isOp("(") || toks[i-1].isOp(",")) && i+1 < len(toks) && toks[i+1].isOp("=") {
			continue
		}
		if !sroPyValidIsInstanceCall(toks, i, isInstTok) {
			return "allowlist: [py-isinstance-call] blocked"
		}
	}

	for i := 0; i < len(toks); i++ {
		if toks[i].isOp(".") && i+2 < len(toks) && toks[i+1].isId("add_argument") && toks[i+2].isOp("(") {
			cp := sroPyMatchDelim(toks, i+2, "(", ")")
			if cp > i+2 {
				sroPyExtractAddArgDest(sroPyParseCallArgs(toks, i+2, cp), userAttrs)
			}
		}
		if toks[i].kind == sroPyId && !importSpanToks[i] && i+1 < len(toks) && toks[i+1].isOp("(") {
			cp := sroPyMatchDelim(toks, i+1, "(", ")")
			if cp > i+1 {
				canon := confCalls[toks[i].val]
				if i >= 2 && toks[i-1].isOp(".") && toks[i-2].kind == sroPyId && confinedMods[toks[i-2].val] != "" {
					canon = confinedMods[toks[i-2].val] + "." + toks[i].val
				}
				if canon == "collections.namedtuple" {
					sroPyExtractNamedtupleFields(sroPyParseCallArgs(toks, i+1, cp), userAttrs)
				} else if canon == "argparse.Namespace" || canon == "types.SimpleNamespace" {
					for _, a := range sroPyParseCallArgs(toks, i+1, cp) {
						if !a.isStar && !a.isKwStar && a.kw != "" && !strings.HasPrefix(a.kw, "_") && !sroPyNonROMembers[a.kw] {
							userAttrs[a.kw] = true
						}
					}
				}
			}
		}
	}

	reflModTok := make(map[int]bool)
	validStdioTok := make(map[int]bool)
	for i := 0; i < len(toks); i++ {
		if importSpanToks[i] || toks[i].kind != sroPyId || (i > 0 && toks[i-1].isOp(".")) {
			continue
		}
		if !defParamToks[i] && i > 0 && (toks[i-1].isOp("(") || toks[i-1].isOp(",")) && i+1 < len(toks) && toks[i+1].isOp("=") {
			continue
		}
		if toks[i].val == "getattr" {
			cArgs, attrStr, okG := sroPyValidGetattrArgs(toks, i)
			if !okG {
				return "allowlist: [py-getattr-syntax] blocked"
			}
			if len(cArgs) == 0 {
				continue
			}
			objSeg := cArgs[0].val
			if len(objSeg) == 3 && objSeg[0].kind == sroPyId && objSeg[1].isOp(".") && objSeg[2].kind == sroPyId && confinedMods[objSeg[0].val] != "" {
				return "allowlist: [py-getattr-confined-dot] getattr on confined symbol " + objSeg[0].val + "." + objSeg[2].val + " not allowed"
			}
			if len(objSeg) == 1 && objSeg[0].kind == sroPyId {
				oName := objSeg[0].val
				if confCalls[oName] != "" || confValCls[oName] != "" {
					return "allowlist: [py-getattr-confined-sym] getattr on confined symbol " + oName + " not allowed"
				}
				if canonMod := confinedMods[oName]; canonMod != "" {
					exports := sroPyModExports[canonMod]
					kind, okExp := exports[attrStr]
					if !okExp || kind != sroPyExpConst || attrStr == "environ" || attrStr == "stdout" || attrStr == "stderr" || attrStr == "stdin" {
						return "allowlist: [py-getattr-mod] getattr module member " + canonMod + "." + attrStr + " not allowed"
					}
					reflModTok[cArgs[0].valStart] = true
					continue
				}
			}
			if !sroPyUncalledMeths[attrStr] && !sroPyDataAttrs[attrStr] && !userAttrs[attrStr] {
				return "allowlist: [py-getattr-attr] getattr attribute ." + attrStr + " not allowed"
			}
		} else if toks[i].val == "vars" {
			if !sroPyValidVarsCall(toks, i, confinedMods, reflModTok) {
				return "allowlist: [py-vars-call] blocked"
			}
		}
	}

	for i := 0; i < len(toks); i++ {
		if importSpanToks[i] {
			continue
		}
		if toks[i].isId("print") && (i == 0 || !toks[i-1].isOp(".")) && i+1 < len(toks) && toks[i+1].isOp("(") {
			cp := sroPyMatchDelim(toks, i+1, "(", ")")
			for _, a := range sroPyParseCallArgs(toks, i+1, cp) {
				if a.kw == "file" {
					sroPyIsStdioOrNone(a.val, a.valStart, confinedMods, validStdioTok)
				}
			}
		}
		if toks[i].isOp(".") && i+2 < len(toks) && toks[i+1].isId("printdir") && toks[i+2].isOp("(") {
			cp := sroPyMatchDelim(toks, i+2, "(", ")")
			pArgs := sroPyParseCallArgs(toks, i+2, cp)
			if len(pArgs) == 1 {
				sroPyIsStdioOrNone(pArgs[0].val, pArgs[0].valStart, confinedMods, validStdioTok)
			}
		}
	}

	skipUntil := -1
	for i := 0; i < len(toks); i++ {
		if i <= skipUntil || importSpanToks[i] {
			continue
		}
		t := toks[i]
		if t.kind != sroPyId {
			continue
		}

		isAfterDot := i > 0 && toks[i-1].isOp(".")
		isCallKwName := !isAfterDot && !defParamToks[i] && i > 0 && (toks[i-1].isOp("(") || toks[i-1].isOp(",")) && i+1 < len(toks) && toks[i+1].isOp("=")
		if isCallKwName {
			continue
		}

		if !isAfterDot && sroPyBadIdents[t.val] {
			return "allowlist: [py-forbidden-ident] identifier " + t.val + " not allowed"
		}

		if !isAfterDot && (confinedMods[t.val] != "" || environVars[t.val]) {
			if environVars[t.val] {
				if !sroPyCheckEnvironUse(toks, i) {
					return "allowlist: [py-environ-alias-use] blocked"
				}
				continue
			}
			if reflModTok[i] {
				continue
			}
			if i+1 >= len(toks) || !toks[i+1].isOp(".") {
				return "allowlist: [py-mod-bare] module " + t.val + " must be accessed via .member"
			}
			curMod := confinedMods[t.val]
			curIdx := i
			for {
				member := toks[curIdx+2].val
				expMap := sroPyModExports[curMod]
				expKind, okExp := expMap[member]
				if !okExp {
					return "allowlist: [py-mod-member] module member " + curMod + "." + member + " not allowed"
				}
				memberIdx := curIdx + 2
				if expKind == sroPyExpSubmod {
					if memberIdx+1 >= len(toks) || !toks[memberIdx+1].isOp(".") {
						return "allowlist: [py-submod-bare] submodule " + curMod + "." + member + " must be accessed via .member"
					}
					curMod = curMod + "." + member
					curIdx = memberIdx
					continue
				}

				canon := curMod + "." + member
				if canon == "os.environ" {
					if !sroPyCheckEnvironUse(toks, memberIdx) {
						return "allowlist: [py-environ-use] blocked"
					}
					skipUntil = memberIdx
					break
				}
				if canon == "sys.stdout" || canon == "sys.stderr" || canon == "sys.stdin" {
					if validStdioTok[memberIdx] {
						skipUntil = memberIdx
						break
					}
					if !sroPyCheckStdioDirectUse(toks, memberIdx, member, &skipUntil) {
						return "allowlist: [py-stdio-use] unconfined sys." + member + " alias not allowed"
					}
					break
				}
				if canon == "sys.path" {
					if !sroPyCheckSysPathUse(toks, memberIdx) {
						return "allowlist: [py-sys-path-mutate] blocked"
					}
					skipUntil = memberIdx
					break
				}

				if expKind == sroPyExpCall {
					isDecorator := i > 0 && toks[i-1].isOp("@") && canon == "dataclasses.dataclass"
					if strings.HasPrefix(canon, "pathlib.") && memberIdx+3 < len(toks) &&
						toks[memberIdx+1].isOp(".") && toks[memberIdx+2].kind == sroPyId &&
						(toks[memberIdx+2].val == "cwd" || toks[memberIdx+2].val == "home") && toks[memberIdx+3].isOp("(") {
						skipUntil = memberIdx + 2
						break
					}
					if isInstTok[memberIdx] || clsBaseTok[memberIdx] || (isDecorator && (memberIdx+1 >= len(toks) || !toks[memberIdx+1].isOp("("))) {
						skipUntil = memberIdx
						break
					}
					if memberIdx+1 >= len(toks) || !toks[memberIdx+1].isOp("(") {
						return "allowlist: [py-mod-callable] " + canon + " must be called directly"
					}
					cp := sroPyMatchDelim(toks, memberIdx+1, "(", ")")
					if hit := sroPyCheckSpecialCallable(canon, sroPyParseCallArgs(toks, memberIdx+1, cp), confinedMods, validStdioTok, userAttrs); hit != "" {
						return hit
					}
				} else if expKind == sroPyExpValueCls {
					if !isInstTok[memberIdx] {
						hasCall := memberIdx+1 < len(toks) && toks[memberIdx+1].isOp("(")
						hasDot := memberIdx+1 < len(toks) && toks[memberIdx+1].isOp(".")
						if !hasCall && !hasDot {
							return "allowlist: [py-mod-valcls] " + canon + " must be called or accessed via .member"
						}
					}
				}
				skipUntil = memberIdx
				break
			}
			continue
		}

		if !isAfterDot && confCalls[t.val] != "" {
			canon := confCalls[t.val]
			isDecorator := i > 0 && toks[i-1].isOp("@") && canon == "dataclasses.dataclass"
			if strings.HasPrefix(canon, "pathlib.") && i+3 < len(toks) &&
				toks[i+1].isOp(".") && toks[i+2].kind == sroPyId &&
				(toks[i+2].val == "cwd" || toks[i+2].val == "home") && toks[i+3].isOp("(") {
				skipUntil = i + 2
				continue
			}
			if isInstTok[i] || clsBaseTok[i] || (isDecorator && (i+1 >= len(toks) || !toks[i+1].isOp("("))) {
				continue
			}
			if i+1 >= len(toks) || !toks[i+1].isOp("(") {
				return "allowlist: [py-imp-callable] imported callable " + t.val + " must be called directly"
			}
			cp := sroPyMatchDelim(toks, i+1, "(", ")")
			if hit := sroPyCheckSpecialCallable(canon, sroPyParseCallArgs(toks, i+1, cp), confinedMods, validStdioTok, userAttrs); hit != "" {
				return hit
			}
			continue
		}
		if !isAfterDot && confValCls[t.val] != "" {
			if !isInstTok[i] {
				hasCall := i+1 < len(toks) && toks[i+1].isOp("(")
				hasDot := i+1 < len(toks) && toks[i+1].isOp(".")
				if !hasCall && !hasDot {
					return "allowlist: [py-imp-valcls] imported class " + t.val + " must be called or accessed via .member"
				}
			}
			continue
		}

		if !isAfterDot && t.val == "open" {
			if i+1 >= len(toks) || !toks[i+1].isOp("(") {
				return "allowlist: [py-bare-open] blocked"
			}
			cp := sroPyMatchDelim(toks, i+1, "(", ")")
			if hit := sroPyOpenHit(sroPyParseCallArgs(toks, i+1, cp), true, false, false); hit != "" {
				return hit
			}
			continue
		}

		if !isAfterDot && t.val == "print" {
			if i+1 >= len(toks) || !toks[i+1].isOp("(") {
				return "allowlist: [py-print-bare] blocked"
			}
			cp := sroPyMatchDelim(toks, i+1, "(", ")")
			if !sroPyValidPrintArgs(sroPyParseCallArgs(toks, i+1, cp), confinedMods, validStdioTok) {
				return "allowlist: [py-print-file] blocked"
			}
			continue
		}

		if !isAfterDot && t.val == "type" {
			if !isInstTok[i] && !sroPyCheckTypeCallContext(toks, i) {
				return "allowlist: [py-type-call] blocked"
			}
			continue
		}

		if isAfterDot {
			attr := t.val
			if sroPyIsDunderOrMangled(attr) {
				continue
			}
			isCall := i+1 < len(toks) && toks[i+1].isOp("(")
			recvTok := toks[i-2]
			isBareSelf := recvTok.isId("self") && (i < 3 || !toks[i-3].isOp("."))

			if isCall {
				cp := sroPyMatchDelim(toks, i+1, "(", ")")
				if strings.HasPrefix(attr, "_") {
					if isBareSelf && userPrivMeths[attr] {
						continue
					}
					return "allowlist: [py-priv-method] private method call ." + attr + "() not allowed"
				}
				switch attr {
				case "open":
					isDbmOpen := !importedNames["dbm"] && !locallyBound["dbm"] &&
						((recvTok.isId("dbm") && (i < 3 || !toks[i-3].isOp("."))) ||
							(i >= 4 && recvTok.kind == sroPyId &&
								(recvTok.val == "gnu" || recvTok.val == "ndbm" || recvTok.val == "dumb") &&
								toks[i-3].isOp(".") && toks[i-4].isId("dbm") && (i < 5 || !toks[i-5].isOp("."))))
					isLegacyModOpen := recvTok.kind == sroPyId && sroPyLegacyModuleOpens[recvTok.val] &&
						!importedNames[recvTok.val] && !locallyBound[recvTok.val] && (i < 3 || !toks[i-3].isOp("."))
					if hit := sroPyOpenHitExt(sroPyParseCallArgs(toks, i+1, cp), false, false, false, !isLegacyModOpen, isDbmOpen, isLegacyModOpen); hit != "" {
						return hit
					}
				case "replace":
					if !sroPyCheckDotReplaceCall(sroPyParseCallArgs(toks, i+1, cp)) {
						return "allowlist: [py-replace-call] blocked"
					}
				case "copy":
					if len(sroPyParseCallArgs(toks, i+1, cp)) != 0 {
						return "allowlist: [py-copy-call] blocked"
					}
				case "printdir":
					if !sroPyValidPrintdirArgs(sroPyParseCallArgs(toks, i+1, cp), confinedMods, validStdioTok) {
						return "allowlist: [py-printdir-file] blocked"
					}
				case "execute":
					if !sroPyReadonlySQL(sroPyParseCallArgs(toks, i+1, cp)) {
						return "allowlist: [py-sqlite-sql] blocked"
					}
				default:
					if !sroPyDirectMeths[attr] && !userMeths[attr] {
						return "allowlist: [py-method-call] method call ." + attr + "() not allowed"
					}
				}
				continue
			}

			if lhsAttrValidTok[i] {
				continue
			}
			if recvTok.isId("dbm") && !importedNames["dbm"] && !locallyBound["dbm"] &&
				(attr == "gnu" || attr == "ndbm" || attr == "dumb") &&
				i+3 < len(toks) && toks[i+1].isOp(".") && toks[i+2].isId("open") && toks[i+3].isOp("(") {
				continue
			}
			if strings.HasPrefix(attr, "_") {
				if isBareSelf && selfPrivAttrs[attr] {
					continue
				}
				return "allowlist: [py-priv-attr] private attribute ." + attr + " not allowed"
			}
			if !sroPyUncalledMeths[attr] && !sroPyDataAttrs[attr] && !userAttrs[attr] {
				return "allowlist: [py-uncalled-attr] attribute ." + attr + " not allowed"
			}
		}
	}

	return ""
}

func sroPyCheckEnvironUse(toks []sroPyTok, idx int) bool {
	if idx > 0 && toks[idx-1].isId("in") &&
		(idx+1 >= len(toks) || (!toks[idx+1].isOp(".") && !toks[idx+1].isOp("[") && !sroPyIsAnyAssignOp(toks[idx+1]))) {
		if idx < 2 || toks[idx-2].kind != sroPyId || toks[idx-2].val != "for" {
			return true
		}
	}
	if idx >= 2 && toks[idx-1].isOp("(") && idx+1 < len(toks) && toks[idx+1].isOp(")") &&
		toks[idx-2].kind == sroPyId && (toks[idx-2].val == "dict" || toks[idx-2].val == "len" || toks[idx-2].val == "list") {
		return true
	}
	if idx+1 >= len(toks) {
		return false
	}
	if toks[idx+1].isOp("[") {
		cb := sroPyMatchDelim(toks, idx+1, "[", "]")
		return cb >= 0 && (cb+1 >= len(toks) || !sroPyIsAnyAssignOp(toks[cb+1]))
	}
	if toks[idx+1].isOp(".") && idx+3 < len(toks) && toks[idx+2].kind == sroPyId && toks[idx+3].isOp("(") {
		switch toks[idx+2].val {
		case "get", "keys", "values", "items", "copy":
			return true
		}
	}
	return false
}

func sroPyCheckStdioDirectUse(toks []sroPyTok, memberIdx int, member string, skipUntil *int) bool {
	if member == "stdin" {
		if memberIdx+3 < len(toks) && toks[memberIdx+1].isOp(".") && toks[memberIdx+2].kind == sroPyId &&
			(toks[memberIdx+2].val == "read" || toks[memberIdx+2].val == "readline" || toks[memberIdx+2].val == "readlines") &&
			toks[memberIdx+3].isOp("(") {
			*skipUntil = memberIdx + 2
			return true
		}
		if memberIdx >= 3 && (toks[memberIdx-3].isOp("(") || toks[memberIdx-3].isOp(",") ||
			(toks[memberIdx-3].isId("in"))) {
			*skipUntil = memberIdx
			return true
		}
		return false
	}
	if memberIdx+3 < len(toks) && toks[memberIdx+1].isOp(".") && toks[memberIdx+2].kind == sroPyId &&
		(toks[memberIdx+2].val == "write" || toks[memberIdx+2].val == "flush") && toks[memberIdx+3].isOp("(") {
		*skipUntil = memberIdx + 2
		return true
	}
	return false
}

func sroPyCheckSysPathUse(toks []sroPyTok, memberIdx int) bool {
	if memberIdx+1 < len(toks) {
		if sroPyIsAnyAssignOp(toks[memberIdx+1]) || toks[memberIdx+1].isOp(".") {
			return false
		}
		if toks[memberIdx+1].isOp("[") {
			cb := sroPyMatchDelim(toks, memberIdx+1, "[", "]")
			if cb < 0 || (cb+1 < len(toks) && sroPyIsAnyAssignOp(toks[cb+1])) {
				return false
			}
		}
	}
	return true
}

func sroPyCheckTypeCallContext(toks []sroPyTok, typeIdx int) bool {
	if typeIdx > 0 {
		prev := toks[typeIdx-1]
		if prev.isOp("==") || prev.isOp("!=") || prev.isOp("<") || prev.isOp("<=") || prev.isOp(">") || prev.isOp(">=") ||
			(prev.kind == sroPyId && (prev.val == "is" || prev.val == "in" || prev.val == "not")) {
			return false
		}
	}
	if typeIdx+1 >= len(toks) || !toks[typeIdx+1].isOp("(") {
		return false
	}
	cp := sroPyMatchDelim(toks, typeIdx+1, "(", ")")
	if cp < 0 {
		return false
	}
	cArgs := sroPyParseCallArgs(toks, typeIdx+1, cp)
	if len(cArgs) != 1 || cArgs[0].isStar || cArgs[0].isKwStar || cArgs[0].kw != "" {
		return false
	}
	if cp+2 < len(toks) && toks[cp+1].isOp(".") && toks[cp+2].kind == sroPyId &&
		(toks[cp+2].val == "__name__" || toks[cp+2].val == "__qualname__") {
		return true
	}
	if cp+2 < len(toks) {
		opIdx := cp + 1
		targetIdx := cp + 2
		if toks[opIdx].isId("is") {
			if targetIdx < len(toks) && toks[targetIdx].isId("not") {
				targetIdx++
			}
		} else if !toks[opIdx].isOp("==") && !toks[opIdx].isOp("!=") {
			return false
		}
		if targetIdx < len(toks) && toks[targetIdx].kind == sroPyId && sroPyTypeCmpBuiltins[toks[targetIdx].val] {
			if targetIdx+1 >= len(toks) {
				return true
			}
			after := toks[targetIdx+1]
			if !after.isOp("(") && !after.isOp("[") && !after.isOp(".") &&
				!after.isOp("==") && !after.isOp("!=") && !after.isOp("<") && !after.isOp("<=") && !after.isOp(">") && !after.isOp(">=") &&
				!(after.kind == sroPyId && (after.val == "is" || after.val == "in")) {
				return true
			}
		}
	}
	return false
}

func sroPyCheckDotReplaceCall(args []sroPyCallArg) bool {
	posCount := 0
	kwCount := 0
	onlyCountKw := true
	allDatetimeKw := true
	for _, a := range args {
		if a.isStar || a.isKwStar {
			return false
		}
		if a.kw != "" {
			kwCount++
			if a.kw != "count" {
				onlyCountKw = false
			}
			if !sroPyReplaceKw[a.kw] {
				allDatetimeKw = false
			}
		} else {
			posCount++
		}
	}
	if posCount >= 2 && posCount <= 3 && onlyCountKw && posCount+kwCount <= 3 {
		return true
	}
	if posCount == 0 && kwCount >= 1 && allDatetimeKw {
		return true
	}
	return false
}
