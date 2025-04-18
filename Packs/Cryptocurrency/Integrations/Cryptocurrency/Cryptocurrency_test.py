import demistomock as demisto
import pytest
from Cryptocurrency import main

INTEGRATION_NAME = "Cryptocurrency"


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, "callingContext", {"context": {"IntegrationBrand": INTEGRATION_NAME}})


@pytest.mark.parametrize(
    "crypto,expected",
    [
        (
            "bitcoin:1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            {
                "Cryptocurrency(val.Address && val.Address == obj.Address)": [
                    {"Address": "bitcoin:1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", "AddressType": "bitcoin"}
                ],
                "DBotScore("
                "val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
                    {
                        "Indicator": "bitcoin:1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
                        "Type": "cryptocurrency",
                        "Vendor": "Cryptocurrency",
                        "Score": 2,
                        "Reliability": "B - Usually reliable",
                    }
                ],
            },
        ),
        (
            "bitcoin:1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9,1ANNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            {
                "Cryptocurrency(val.Address && val.Address == obj.Address)": [
                    {"Address": "bitcoin:1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9", "AddressType": "bitcoin"}
                ],
                "DBotScore("
                "val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
                    {
                        "Indicator": "bitcoin:1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9",
                        "Type": "cryptocurrency",
                        "Vendor": "Cryptocurrency",
                        "Score": 2,
                        "Reliability": "B - Usually reliable",
                    }
                ],
            },
        ),
    ],
)
def test_main__without_address_type(mocker, crypto, expected):
    """
    Given
    - cryptocurrency addresses.
    When
    - When cryptocurrency addresses were auto extracted/received by the user
    Then
    - Returns List of CommandResults object with the expected data
    """
    mocker.patch.object(demisto, "args", return_value={"crypto": crypto})
    mocker.patch.object(demisto, "params", return_value={"reliability": "B - Usually reliable", "reputation": "Suspicious"})
    mocker.patch.object(demisto, "command", return_value="crypto")
    mocker.patch.object(demisto, "results")
    main()
    assert expected == demisto.results.call_args[0][0]["EntryContext"]


def test_main__with_address_type(mocker):
    """
    Given
    - cryptocurrency addresses.
    - address_type arg with 'bitcoin' value.
    When
    - When cryptocurrency addresses were received by the user.
    Then
    - Returns List of CommandResults object with the expected data
    """
    crypto = "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"
    expected = {
        "Cryptocurrency(val.Address && val.Address == obj.Address)": [
            {"Address": "bitcoin:1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", "AddressType": "bitcoin"}
        ],
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": [
            {
                "Indicator": "bitcoin:1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
                "Type": "cryptocurrency",
                "Vendor": "Cryptocurrency",
                "Score": 0,
                "Reliability": "A - Completely reliable",
            }
        ],
    }
    mocker.patch.object(demisto, "args", return_value={"crypto": crypto, "address_type": "bitcoin"})
    mocker.patch.object(demisto, "params", return_value={"reliability": "A - Completely reliable", "reputation": "None"})
    mocker.patch.object(demisto, "command", return_value="crypto")
    mocker.patch.object(demisto, "results")
    main()
    assert expected == demisto.results.call_args[0][0]["EntryContext"]
