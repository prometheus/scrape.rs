help "test_histogram1" "Similar histogram as before but now without sparse buckets."
type "test_histogram1" histogram
histogram "test_histogram1" - int schema=-53 count=175 sum=3f4b21c475e6362a zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[0:4] pos=[2,0,10,147] neg_spans=[] neg=[] custom=[bf3f75104d551d69,bf38e757928e0c9e,3ff0000000000000] "__name__"="test_histogram1"
exemplar bf38e757928e0c9e 1625851153146 "dummyID"="59727"
st 0
help "test_histogram2_seconds" "Similar histogram as before but now with integer buckets."
unit "test_histogram2_seconds" "seconds"
type "test_histogram2_seconds" histogram
histogram "test_histogram2_seconds" - int schema=-53 count=6 sum=4049000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[0:3] pos=[2,0,0] neg_spans=[] neg=[] custom=[c034000000000000,4034000000000000,403e000000000000] "__name__"="test_histogram2_seconds"
exemplar 402e000000000000 1625851153146 "dummyID"="59727"
exemplar 4039000000000000 1625851153146 "dummyID"="5617"
st 0
help "test_histogram_family" "Test histogram metric family with two very simple histograms."
type "test_histogram_family" histogram
histogram "test_histogram_familyÿfooÿbar" - int schema=-53 count=5 sum=4028333333333333 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[0:3] pos=[2,-1,1] neg_spans=[] neg=[] custom=[3ff199999999999a,400199999999999a] "__name__"="test_histogram_family" "foo"="bar"
st 0
histogram "test_histogram_familyÿfooÿbaz" - int schema=-53 count=6 sum=402a333333333333 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[1:2] pos=[5,-4] neg_spans=[] neg=[] custom=[3ff199999999999a,400199999999999a] "__name__"="test_histogram_family" "foo"="baz"
st 0
help "empty_histogram" "A histogram without observations and with a zero threshold of zero but with a no-op span to identify it as a native histogram."
type "empty_histogram" histogram
histogram "empty_histogram" - int schema=0 count=0 sum=0000000000000000 zero_threshold=0000000000000000 zero_count=0 hint=0 pos_spans=[] pos=[] neg_spans=[] neg=[] custom=[] "__name__"="empty_histogram"
st 0
