help "float_unsorted" "Float counts, unsorted and repeated bounds, no +Inf bucket."
type "float_unsorted" gaugehistogram
histogram "float_unsortedÿjobÿa" 1234568 float schema=-53 count=401e000000000000 sum=4028800000000000 zero_threshold=0000000000000000 zero_count=0000000000000000 hint=3 pos_spans=[0:3] pos=[3fe0000000000000,4000000000000000,4014000000000000] neg_spans=[] neg=[] custom=[fff0000000000000,3ff0000000000000,4024000000000000,4034000000000000] "__name__"="float_unsorted" "job"="a"
exemplar 4022000000000000 1625851153146 "id"="x"
st 1625851100000
help "int_empty_runs" "Leading, short, long, and trailing runs of empty buckets."
type "int_empty_runs" histogram
histogram "int_empty_runs" - int schema=-53 count=9 sum=4044000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[1:4,3:1] pos=[2,-2,0,2,3] neg_spans=[] neg=[] custom=[3fe0000000000000,3ff0000000000000,4000000000000000,4008000000000000,4010000000000000,4014000000000000,4018000000000000,401c000000000000,4020000000000000,4022000000000000,4026000000000000] "__name__"="int_empty_runs"
st 0
histogram "int_empty_runsÿemptyÿhistogram" - int schema=-53 count=0 sum=0000000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="int_empty_runs" "empty"="histogram"
st 0
histogram "int_empty_runsÿmissingÿhistogram" - int schema=-53 count=0 sum=0000000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="int_empty_runs" "missing"="histogram"
st 0
help "float_empty_buckets" "Float counts with empty buckets, compacted without gaps."
type "float_empty_buckets" histogram
histogram "float_empty_buckets" - float schema=-53 count=400c000000000000 sum=3ff0000000000000 zero_threshold=0000000000000000 zero_count=0000000000000000 hint=0 pos_spans=[0:1,1:1] pos=[3ff8000000000000,4000000000000000] neg_spans=[] neg=[] custom=[3ff0000000000000,4000000000000000,4008000000000000] "__name__"="float_empty_buckets"
st 0
help "mixed" "Native and classic histograms in one family."
type "mixed" histogram
histogram "mixedÿkindÿnative" - int schema=0 count=2 sum=4008000000000000 zero_threshold=3f50624dd2f1a9fc zero_count=0 hint=0 pos_spans=[0:1] pos=[2] neg_spans=[] neg=[] custom=[] "__name__"="mixed" "kind"="native"
exemplar 3ff0000000000000 1000 "id"="native"
st 0
histogram "mixedÿkindÿclassic" - int schema=-53 count=2 sum=4008000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[0:2] pos=[1,0] neg_spans=[] neg=[] custom=[3ff0000000000000,4014000000000000] "__name__"="mixed" "kind"="classic"
exemplar 4010000000000000 2000 "id"="classic"
st 0
histogram "mixedÿkindÿnative-again" - int schema=0 count=1 sum=3ff0000000000000 zero_threshold=3f50624dd2f1a9fc zero_count=1 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="mixed" "kind"="native-again"
st 0
histogram "mixedÿkindÿfloat-native" - float schema=0 count=400c000000000000 sum=4000000000000000 zero_threshold=3f50624dd2f1a9fc zero_count=0000000000000000 hint=0 pos_spans=[0:1] pos=[3ff8000000000000] neg_spans=[1:1] neg=[4000000000000000] custom=[] "__name__"="mixed" "kind"="float-native"
st 0
histogram "mixedÿkindÿfloat-classic" - float schema=-53 count=4004000000000000 sum=4008000000000000 zero_threshold=0000000000000000 zero_count=0000000000000000 hint=0 pos_spans=[0:2] pos=[3ff8000000000000,3ff0000000000000] neg_spans=[] neg=[] custom=[3ff0000000000000,4014000000000000] "__name__"="mixed" "kind"="float-classic"
st 0
histogram "mixedÿkindÿfloat-native-again" - float schema=0 count=3ff8000000000000 sum=3ff0000000000000 zero_threshold=3f50624dd2f1a9fc zero_count=3ff8000000000000 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="mixed" "kind"="float-native-again"
st 0
help "float_nan_count" "A NaN cumulative count followed by a finite one."
type "float_nan_count" histogram
histogram "float_nan_count" - float schema=-53 count=400c000000000000 sum=3ff0000000000000 zero_threshold=0000000000000000 zero_count=0000000000000000 hint=0 pos_spans=[0:3] pos=[7ff8000000000001,7ff8000000000001,3ff0000000000000] neg_spans=[] neg=[] custom=[3ff0000000000000,4000000000000000] "__name__"="float_nan_count"
st 0
