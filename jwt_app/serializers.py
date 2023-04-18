from rest_framework import serializers


class DummySerializer(serializers.Serializer):
    """
    we can use the validate method or validate_ParamName method for any additional validation
    """
    required_param = serializers.CharField(required=True)
    optional_param1 = serializers.IntegerField(required=False)
    optional_param2 = serializers.CharField(required=False)
    list_param = serializers.ListField(required=False)
    list_of_lists = serializers.ListField(child=serializers.ListField(), required=False)
    list_of_lists_list = serializers.ListField(child=serializers.ListField(
        child=serializers.ListField()), required=False)
    dict_param = serializers.DictField(required=False)
    dict_of_lists = serializers.DictField(child=serializers.ListField(), required=False)
    dict_of_lists_of_dicts = serializers.DictField(child=serializers.ListField(
        child=serializers.DictField(), required=False))

    def validate_required_param(self, value):
        if value == 'hello':
            raise serializers.ValidationError("required_param cannot be 'hello'")
        return value

